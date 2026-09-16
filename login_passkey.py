"""使用已导出的 NUIST 软件 passkey 登录。

安装依赖：
    python -m pip install requests cryptography

用法（新版本 bundle 已包含 userId 和 anonbiometricsd）：
    python login_passkey.py passkey.json

旧 bundle 也可手工补充参数：
    python login_passkey.py passkey.json --username 202563160021 \
        --user-id MjAyNTYzMTYwMDIx \
        --start-id fc91fc4bf8a84cdea6fc8010de48a8ca

passkey.json 是 browser_passkey.js 输出的 bundle，例如：
{
  "rpId": "authserver.nuist.edu.cn",
  "credentialId": "...",
  "privateKeyPkcs8Pem": "-----BEGIN PRIVATE KEY-----..."
}

脚本不会保存或硬编码 Cookie。每次运行都会创建新的 requests.Session，
先访问登录页获取 JSESSIONID/route，再调用 startAssertion 和 login。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

BASE_URL = "https://authserver.nuist.edu.cn"
LOGIN_URL = f"{BASE_URL}/authserver/login"
START_ASSERTION_URL = f"{BASE_URL}/authserver/startAssertion"


def make_login_url(service: str | None = None) -> str:
    """登录页 URL；带 service 时用于登录后跳转到目标业务系统。"""
    if not service:
        return LOGIN_URL
    return f"{LOGIN_URL}?service={requests.utils.quote(service, safe=':/')}"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    value = value.replace("-", "+").replace("_", "/")
    return base64.b64decode(value + "=" * (-len(value) % 4))


def user_id_from_username(username: str) -> str:
    """抓包中的 userId 是学号的 Base64URL（无 padding）。"""
    return b64url_encode(username.encode("utf-8"))


def load_bundle(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """bundle 可以是文件路径、JSON 文本，或已经解析好的 dict。"""
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
                raise RuntimeError(f"读取 bundle 失败：{exc}") from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"解析 bundle 失败：{exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("bundle 必须是 JSON 对象")

    for name in ("rpId", "credentialId"):
        if not data.get(name):
            raise RuntimeError(f"bundle 缺少字段：{name}")
    if not data.get("privateKeyPkcs8Pem") and not data.get("privateKeyJwk"):
        raise RuntimeError("bundle 缺少 privateKeyPkcs8Pem/privateKeyJwk")
    return data


def load_private_key(bundle: dict[str, Any]) -> ec.EllipticCurvePrivateKey:
    if bundle.get("privateKeyPkcs8Pem"):
        key = serialization.load_pem_private_key(
            bundle["privateKeyPkcs8Pem"].encode("ascii"), password=None
        )
    else:
        jwk = bundle["privateKeyJwk"]
        try:
            scalar = int.from_bytes(b64url_decode(jwk["d"]), "big")
        except (KeyError, ValueError, base64.binascii.Error) as exc:
            raise RuntimeError("privateKeyJwk 不是有效的 P-256 JWK") from exc
        key = ec.derive_private_key(scalar, ec.SECP256R1())

    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise RuntimeError("passkey 私钥必须是 P-256/ES256")
    return key


def create_session(login_url: str = LOGIN_URL) -> tuple[requests.Session, str]:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) "
                "Gecko/20100101 Firefox/155.0"
            ),
            "Accept-Language": "zh-CN,en;q=0.9,en-US;q=0.8",
        }
    )
    response = session.get(
        login_url,
        headers={"Accept": "text/html,application/xhtml+xml"},
        timeout=30,
    )
    response.raise_for_status()

    # execution 会话参数通常位于登录页隐藏 input；抓包值 e1s1 作为后备。
    match = re.search(
        r'name=["\']execution["\'][^>]*value=["\']([^"\']+)',
        html.unescape(response.text),
        re.IGNORECASE,
    )
    execution = match.group(1) if match else "e1s1"
    return session, execution


def start_assertion(
    session: requests.Session,
    user_id: str,
    start_id: str,
    login_url: str = LOGIN_URL,
) -> dict[str, Any]:
    response = session.post(
        START_ASSERTION_URL,
        json={"userId": user_id, "id": start_id},
        headers={
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/json;charset=utf-8",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": BASE_URL,
            "Referer": login_url,
        },
        timeout=30,
    )
    response.raise_for_status()
    body = response.json()
    if body.get("success") is False:
        raise RuntimeError(f"startAssertion 失败：{body}")

    request = body.get("result", {}).get("request")
    if not isinstance(request, dict):
        request = body.get("datas", {}).get("request")
    if not isinstance(request, dict):
        raise RuntimeError(f"响应中没有 result.request：{body}")
    if not request.get("requestId"):
        raise RuntimeError(f"startAssertion 响应缺少 requestId：{body}")
    return request


def make_assertion(
    request_data: dict[str, Any],
    bundle: dict[str, Any],
    private_key: ec.EllipticCurvePrivateKey,
    origin: str,
    user_handle: str | None,
) -> dict[str, Any]:
    options = request_data.get("publicKeyCredentialRequestOptions", {})
    challenge = options.get("challenge")
    rp_id = options.get("rpId") or bundle["rpId"]
    credential_id = bundle["credentialId"]
    if not challenge or not rp_id:
        raise RuntimeError("startAssertion 缺少 challenge/rpId")

    allowed = options.get("allowCredentials") or []
    if allowed and credential_id not in {
        item.get("id") for item in allowed if isinstance(item, dict)
    }:
        raise RuntimeError(
            "bundle 中的 credentialId 不在 allowCredentials 中，"
            "请确认使用的是同一次注册生成的 passkey.json"
        )

    client_data_json = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": False,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    # startAssertion 的前端强制 userVerification=required，
    # 因此设置 UP(0x01) + UV(0x04) = 0x05，计数器沿用注册脚本的 0。
    authenticator_data = (
        hashlib.sha256(rp_id.encode("utf-8")).digest()
        + b"\x05"
        + b"\x00\x00\x00\x00"
    )
    signed = authenticator_data + hashlib.sha256(client_data_json).digest()
    # WebAuthn ES256 的签名格式与抓包中的 MEUCI... 一致，为 DER 编码。
    signature = private_key.sign(signed, ec.ECDSA(hashes.SHA256()))

    response: dict[str, str] = {
        "authenticatorData": b64url_encode(authenticator_data),
        "clientDataJSON": b64url_encode(client_data_json),
        "signature": b64url_encode(signature),
    }
    if user_handle:
        response["userHandle"] = user_handle

    return {
        "type": "public-key",
        "id": credential_id,
        "response": response,
        "clientExtensionResults": {"appid": False},
    }


def submit_login(
    session: requests.Session,
    username: str,
    request_data: dict[str, Any],
    credential: dict[str, Any],
    execution: str,
    login_url: str = LOGIN_URL,
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
        login_url,
        data={
            "_eventId": "submit",
            "username": username,
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
            "Referer": login_url,
            "Upgrade-Insecure-Requests": "1",
        },
        allow_redirects=False,
        timeout=30,
    )


def login_with_bundle(
    bundle_source: str | Path | dict[str, Any],
    username: str | None = None,
    user_id: str | None = None,
    start_id: str | None = None,
    service: str | None = None,
    origin: str = BASE_URL,
    user_handle: str | None = None,
    follow_redirect: bool = True,
) -> requests.Session:
    """完成一次 Passkey 登录，返回已认证的 requests.Session。

    这是 NuistLogin.NuistLogin 兼容层的实现；bundle 可以是路径、JSON 文本或 dict。
    """
    bundle = load_bundle(bundle_source)
    private_key = load_private_key(bundle)

    resolved_user_id = user_id or bundle.get("userId")
    if not resolved_user_id and username:
        resolved_user_id = user_id_from_username(username)
    if not resolved_user_id:
        raise RuntimeError("缺少 userId：请使用新 bundle，或传入 user_id/username")

    resolved_start_id = start_id or bundle.get("anonbiometricsd")
    if not resolved_start_id:
        raise RuntimeError("缺少 anonbiometricsd：请使用新 bundle，或传入 start_id")

    login_url = make_login_url(service)
    session, execution = create_session(login_url)
    request_data = start_assertion(session, resolved_user_id, resolved_start_id, login_url)
    credential = make_assertion(request_data, bundle, private_key, origin, user_handle)
    # 表单里的 username 字段发的是 Base64URL 的 userId，不是明文学号。
    response = submit_login(
        session, resolved_user_id, request_data, credential, execution, login_url
    )
    if response.status_code not in (301, 302, 303, 307, 308):
        raise RuntimeError(
            f"登录未返回重定向：HTTP {response.status_code}\n"
            f"响应前 500 字符：{response.text[:500]}"
        )

    location = response.headers.get("Location", "")
    if follow_redirect and location:
        landing = session.get(urljoin(login_url, location), allow_redirects=True, timeout=30)
        if "authserver.nuist.edu.cn/authserver/login" in landing.url:
            raise RuntimeError("登录后又跳回认证页，service 可能不正确或凭据已失效")
    return session


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="使用 NUIST passkey 登录")
    parser.add_argument("bundle", type=Path, help="browser_passkey.js 输出的 JSON 文件")
    parser.add_argument("--username", help="旧 bundle 必填；明文学号，例如 202563160021")
    parser.add_argument(
        "--user-id",
        help="可选；优先使用此值，否则读取 bundle.userId，最后按学号生成",
    )
    parser.add_argument(
        "--start-id",
        help="可选；优先使用此值，否则读取 bundle.anonbiometricsd",
    )
    parser.add_argument(
        "--origin", default=BASE_URL, help="clientDataJSON origin，默认 authserver 地址"
    )
    parser.add_argument(
        "--user-handle",
        help="可选；只有抓包 response 中存在 userHandle 时才传入，值保持原始 Base64URL",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        bundle = load_bundle(args.bundle)
        private_key = load_private_key(bundle)
        session, execution = create_session()
        user_id = args.user_id or bundle.get("userId")
        if not user_id and args.username:
            user_id = user_id_from_username(args.username)
        if not user_id:
            raise RuntimeError(
                "缺少 userId：请使用新 bundle，或传入 --user-id/--username"
            )

        start_id = args.start_id or bundle.get("anonbiometricsd")
        if not start_id:
            raise RuntimeError(
                "缺少 anonbiometricsd：请使用新 bundle，或传入 --start-id"
            )

        print(f"已建立新会话，Cookie：{', '.join(session.cookies.keys()) or '(无)'}")
        print(f"userId：{user_id}")
        request_data = start_assertion(session, user_id, start_id)
        credential = make_assertion(
            request_data,
            bundle,
            private_key,
            args.origin,
            args.user_handle,
        )
        response = submit_login(
            session,
            user_id,
            request_data,
            credential,
            execution,
        )

        if response.status_code not in (301, 302, 303, 307, 308):
            raise RuntimeError(
                f"登录未返回重定向：HTTP {response.status_code}\n"
                f"响应前 500 字符：{response.text[:500]}"
            )
        print("登录成功")
        print(f"Location: {response.headers.get('Location', '(空)')}")
        print(f"当前会话 Cookie：{session.cookies.get_dict()}")
        return 0
    except (requests.RequestException, RuntimeError, ValueError, TypeError) as exc:
        print(f"登录失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
