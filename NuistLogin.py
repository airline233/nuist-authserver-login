"""NUIST 统一身份认证登录库（Passkey，纯网络层，不启动浏览器）。

与旧版基于 Playwright 的实现调用方式一致，只把第二个参数从密码换成
Passkey bundle：

    from NuistLogin import NuistLogin

    cookies = NuistLogin("202563160021", "passkey.json", service).login()

bundle 由 ``browser_passkey.js`` 导出，可以传文件路径、JSON 文本，或已经
解析好的 dict，必须包含 ``rpId`` / ``credentialId`` / 私钥，以及
``userId`` 和 ``anonbiometricsd``。旧版 Playwright 实现保留在
``legacy/playwright/NuistLogin.py``，仅供参考。

本模块自成一体，只依赖 requests 和 cryptography。
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from enum import IntEnum
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

BASE_URL = "https://authserver.nuist.edu.cn"
LOGIN_URL = f"{BASE_URL}/authserver/login"
START_ASSERTION_URL = f"{BASE_URL}/authserver/startAssertion"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
)
TIMEOUT = 30


class LogLevel(IntEnum):
    TRACE = 0
    INFO = 1
    ERROR = 2


class CaptchaError(Exception):
    """保留以兼容旧代码；Passkey 登录不涉及图形验证码，不会被抛出。"""


class CredentialError(Exception):
    """bundle 不可用，或服务端拒绝了本次 Passkey 断言。"""


class NuistLogin:
    """用 Passkey 完成 CAS 登录，返回可直接用于业务系统的 Cookie。

    ``headless`` 为兼容旧调用而保留，实际不起作用：本实现不启动浏览器。
    """

    def __init__(
        self,
        username: str,
        passkey: str | Path | dict[str, Any],
        service: str,
        headless: bool = True,
        log_level: LogLevel = LogLevel.ERROR,
    ) -> None:
        self.username = username
        self.passkey = passkey
        self.headless = headless
        self.log_level = log_level
        self.service = service
        self.target_url = self._login_url()
        self.session: requests.Session | None = None

    # ---------- 日志 ----------

    def _log(self, level: LogLevel, message: str) -> None:
        """分级日志输出"""
        if level >= self.log_level:
            prefix = {LogLevel.TRACE: "[-]", LogLevel.INFO: "[*]", LogLevel.ERROR: "[!]"}
            print(f"{prefix.get(level, '[?]')} {message}")

    # ---------- bundle ----------

    def _login_url(self) -> str:
        if not self.service:
            return LOGIN_URL
        return f"{LOGIN_URL}?service={requests.utils.quote(self.service, safe=':/')}"

    def _load_bundle(self) -> dict[str, Any]:
        """bundle 可以是 dict、JSON 文本或 JSON 文件路径。"""
        source = self.passkey
        if isinstance(source, dict):
            data: Any = source
        else:
            text = str(source).strip()
            if text.startswith("{"):
                raw = text
            else:
                try:
                    raw = Path(source).read_text(encoding="utf-8")
                except OSError as exc:
                    raise CredentialError(f"读取 bundle 失败：{exc}") from exc
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise CredentialError(f"解析 bundle 失败：{exc}") from exc

        if not isinstance(data, dict):
            raise CredentialError("bundle 必须是 JSON 对象")
        for name in ("rpId", "credentialId"):
            if not data.get(name):
                raise CredentialError(f"bundle 缺少字段：{name}")
        if not data.get("privateKeyPkcs8Pem") and not data.get("privateKeyJwk"):
            raise CredentialError("bundle 缺少 privateKeyPkcs8Pem/privateKeyJwk")
        return data

    @staticmethod
    def _load_private_key(bundle: dict[str, Any]) -> ec.EllipticCurvePrivateKey:
        try:
            if bundle.get("privateKeyPkcs8Pem"):
                key = serialization.load_pem_private_key(
                    bundle["privateKeyPkcs8Pem"].encode("ascii"), password=None
                )
            else:
                jwk = bundle["privateKeyJwk"]
                scalar = int.from_bytes(_b64url_decode(jwk["d"]), "big")
                key = ec.derive_private_key(scalar, ec.SECP256R1())
        except (KeyError, ValueError, TypeError, base64.binascii.Error) as exc:
            raise CredentialError(f"passkey 私钥无法解析：{exc}") from exc

        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise CredentialError("passkey 私钥必须是 P-256/ES256")
        return key

    def _resolve_ids(self, bundle: dict[str, Any]) -> tuple[str, str]:
        """返回 (userId, startId)。userId 是学号的 Base64URL 形式。"""
        user_id = bundle.get("userId")
        if not user_id and self.username:
            user_id = _b64url_encode(self.username.encode("utf-8"))
        if not user_id:
            raise CredentialError("缺少 userId：请使用新 bundle，或传入 username")
        start_id = bundle.get("anonbiometricsd")
        if not start_id:
            raise CredentialError("缺少 anonbiometricsd：请使用新 bundle")
        return user_id, start_id

    # ---------- CAS 流程 ----------

    def _open_login_page(self, session: requests.Session) -> str:
        """访问登录页拿到 JSESSIONID/route，并取出 execution 令牌。"""
        response = session.get(
            self.target_url,
            headers={"Accept": "text/html,application/xhtml+xml"},
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        match = re.search(
            r'name=["\']execution["\'][^>]*value=["\']([^"\']+)',
            html.unescape(response.text),
            re.IGNORECASE,
        )
        execution = match.group(1) if match else "e1s1"
        self._log(LogLevel.TRACE, f"execution={execution}")
        return execution

    def _start_assertion(
        self, session: requests.Session, user_id: str, start_id: str
    ) -> dict[str, Any]:
        response = session.post(
            START_ASSERTION_URL,
            json={"userId": user_id, "id": start_id},
            headers={
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Content-Type": "application/json;charset=utf-8",
                "X-Requested-With": "XMLHttpRequest",
                "Origin": BASE_URL,
                "Referer": self.target_url,
            },
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        body = response.json()
        if body.get("success") is False:
            raise CredentialError(f"startAssertion 失败：{body}")

        request = body.get("result", {}).get("request")
        if not isinstance(request, dict):
            request = body.get("datas", {}).get("request")
        if not isinstance(request, dict) or not request.get("requestId"):
            raise CredentialError(f"startAssertion 响应中没有有效的 request：{body}")
        return request

    def _make_assertion(
        self,
        request_data: dict[str, Any],
        bundle: dict[str, Any],
        private_key: ec.EllipticCurvePrivateKey,
    ) -> dict[str, Any]:
        options = request_data.get("publicKeyCredentialRequestOptions", {})
        challenge = options.get("challenge")
        rp_id = options.get("rpId") or bundle["rpId"]
        credential_id = bundle["credentialId"]
        if not challenge or not rp_id:
            raise CredentialError("startAssertion 缺少 challenge/rpId")

        allowed = options.get("allowCredentials") or []
        if allowed and credential_id not in {
            item.get("id") for item in allowed if isinstance(item, dict)
        }:
            raise CredentialError(
                "bundle 中的 credentialId 不在 allowCredentials 中，"
                "该 Passkey 可能已被吊销"
            )

        client_data_json = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": challenge,
                "origin": BASE_URL,
                "crossOrigin": False,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        # 前端要求 userVerification，故 flags = UP(0x01) | UV(0x04)；计数器固定 0。
        authenticator_data = (
            hashlib.sha256(rp_id.encode("utf-8")).digest()
            + b"\x05"
            + b"\x00\x00\x00\x00"
        )
        # WebAuthn ES256 签名为 DER 编码。
        signature = private_key.sign(
            authenticator_data + hashlib.sha256(client_data_json).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        return {
            "type": "public-key",
            "id": credential_id,
            "response": {
                "authenticatorData": _b64url_encode(authenticator_data),
                "clientDataJSON": _b64url_encode(client_data_json),
                "signature": _b64url_encode(signature),
            },
            "clientExtensionResults": {"appid": False},
        }

    def _submit_login(
        self,
        session: requests.Session,
        user_id: str,
        request_data: dict[str, Any],
        credential: dict[str, Any],
        execution: str,
    ) -> requests.Response:
        response_json = json.dumps(
            {
                "requestId": request_data["requestId"],
                "credential": credential,
                "sessionToken": None,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return session.post(
            self.target_url,
            data={
                "_eventId": "submit",
                # 表单里的 username 发的是 Base64URL 的 userId，不是明文学号，
                # 传明文学号会被服务端以 401 拒绝。
                "username": user_id,
                "responseJson": response_json,
                "cllt": "fidoLogin",
                "dllt": "generalLogin",
                "lt": "",
                "execution": execution,
            },
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": BASE_URL,
                "Referer": self.target_url,
                "Upgrade-Insecure-Requests": "1",
            },
            allow_redirects=False,
            timeout=TIMEOUT,
        )

    # ---------- 对外接口 ----------

    def login(self) -> dict[str, str]:
        """完成登录并返回 Cookie 字典；失败抛 CredentialError。"""
        bundle = self._load_bundle()
        private_key = self._load_private_key(bundle)
        user_id, start_id = self._resolve_ids(bundle)

        session = requests.Session()
        session.headers.update(
            {"User-Agent": USER_AGENT, "Accept-Language": "zh-CN,en;q=0.9,en-US;q=0.8"}
        )
        self._log(LogLevel.INFO, "正在访问登录页...")
        execution = self._open_login_page(session)
        self._log(LogLevel.INFO, "正在提交 Passkey 断言...")
        request_data = self._start_assertion(session, user_id, start_id)
        credential = self._make_assertion(request_data, bundle, private_key)
        response = self._submit_login(
            session, user_id, request_data, credential, execution
        )
        if response.status_code not in (301, 302, 303, 307, 308):
            raise CredentialError(
                f"登录未返回重定向：HTTP {response.status_code}；"
                "Passkey 可能已失效，请重新注册"
            )

        location = response.headers.get("Location", "")
        if location:
            landing = session.get(
                urljoin(self.target_url, location), allow_redirects=True, timeout=TIMEOUT
            )
            self._log(LogLevel.TRACE, f"落地页：{landing.url}")
            if f"{BASE_URL}/authserver/login" in landing.url:
                raise CredentialError("登录后又跳回认证页，service 可能不正确")

        self.session = session
        self._log(LogLevel.INFO, "登录成功！")
        return session.cookies.get_dict()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    value = value.replace("-", "+").replace("_", "/")
    return base64.b64decode(value + "=" * (-len(value) % 4))
