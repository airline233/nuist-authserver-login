"""Backward-compatible NUIST login module backed by Passkey.

The original module automated the username/password + CAPTCHA page with
Playwright. That implementation is preserved at
``legacy/playwright/NuistLogin.py``. The class name, argument order and
``login()`` return value are unchanged; only the second argument differs: pass
the Passkey bundle instead of the password.

    NuistLogin("2023xxxx", "passkey.local.json", service).login()
    NuistLogin("2023xxxx", bundle_dict, service).login()

The bundle is produced by ``browser_passkey.js`` and must contain ``userId``
and ``anonbiometricsd``; a bundle exported by an older script will not work.
"""

from __future__ import annotations

from enum import IntEnum
from pathlib import Path
from typing import Any

from login_passkey import login_with_bundle, make_login_url


class LogLevel(IntEnum):
    TRACE = 0
    INFO = 1
    ERROR = 2


class CaptchaError(Exception):
    """Kept for source compatibility; Passkey login has no CAPTCHA step."""


class CredentialError(Exception):
    """Raised when the bundle is unusable or the server rejects the assertion."""


class NuistLogin:
    """Compatibility facade exposing the original ``NuistLogin`` API.

    ``headless`` is accepted for compatibility but ignored: no browser is
    started. ``passkey`` may be a path to the JSON bundle, the JSON text
    itself, or an already parsed dict.
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
        self.target_url = make_login_url(service)

    def _log(self, level: LogLevel, message: str) -> None:
        """分级日志输出"""
        if level >= self.log_level:
            prefix = {LogLevel.TRACE: "[-]", LogLevel.INFO: "[*]", LogLevel.ERROR: "[!]"}
            print(f"{prefix.get(level, '[?]')} {message}")

    def login(self) -> dict[str, str]:
        """Authenticate with Passkey and return the session Cookie dictionary."""
        self._log(LogLevel.INFO, "正在使用 Passkey 登录...")
        try:
            session = login_with_bundle(
                self.passkey,
                username=self.username,
                service=self.service,
            )
        except RuntimeError as exc:
            raise CredentialError(str(exc)) from exc
        self._log(LogLevel.INFO, "登录成功！")
        return session.cookies.get_dict()
