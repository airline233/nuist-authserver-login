"""DEPRECATED: original Playwright username/password + CAPTCHA implementation.

Kept only for historical reference. The supported module is the root
``NuistLogin.py`` compatibility facade, which uses Passkey instead.
"""

import time
import re
from playwright.sync_api import sync_playwright
import ddddocr
from enum import IntEnum


class LogLevel(IntEnum):
    TRACE = 0
    INFO = 1
    ERROR = 2


class CaptchaError(Exception):
    """验证码错误"""
    pass


class CredentialError(Exception):
    """用户名或密码错误"""
    pass


class NuistLogin:
    def __init__(self, username, password, service, headless=True, log_level=LogLevel.ERROR):
        self.username = username
        self.password = password
        self.headless = headless
        self.log_level = log_level
        self.ocr = ddddocr.DdddOcr(show_ad=False)
        self.target_url = f"https://authserver.nuist.edu.cn/authserver/login?service={service}"

    def _log(self, level, message):
        """分级日志输出"""
        if level >= self.log_level:
            prefix = {LogLevel.TRACE: "[-]", LogLevel.INFO: "[*]", LogLevel.ERROR: "[!]"}
            print(f"{prefix.get(level, '[?]')} {message}")

    def _get_valid_captcha(self, page):
        """循环获取验证码，直到格式符合 4 位字母+数字。"""
        img_selector = "#captchaImg"
        refresh_selector = ".captcha-refresh"
        max_retries = 10
        for i in range(max_retries):
            page.wait_for_selector(img_selector, state="visible")
            img_bytes = page.locator(img_selector).screenshot()
            code = self.ocr.classification(img_bytes)
            self._log(LogLevel.TRACE, f"第 {i + 1} 次识别结果: {code}")
            if re.match(r"^[a-zA-Z0-9]{4}$", code):
                self._log(LogLevel.TRACE, f"格式校验通过: {code}")
                return code
            self._log(LogLevel.TRACE, "格式校验不通过，刷新验证码...")
            page.locator(refresh_selector).click()
            time.sleep(0.5)
        raise CaptchaError("多次刷新验证码仍未获取到有效格式，请检查网络或 OCR 库")

    def login(self):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context()
            page = context.new_page()
            self._log(LogLevel.INFO, "正在访问登录页...")
            page.goto(self.target_url)
            page.wait_for_selector("#pwdFromId")
            page.fill("#username", self.username)
            page.fill("#password", self.password)
            captcha_div = page.locator("#captchaDiv")
            time.sleep(0.5)
            if captcha_div.is_visible():
                self._log(LogLevel.INFO, "检测到验证码输入框，开始识别流程...")
                page.fill("#captcha", self._get_valid_captcha(page))
            if page.locator("#rememberMe").is_visible():
                page.check("#rememberMe")
            self._log(LogLevel.TRACE, "提交表单...")
            page.click("#login_submit")
            try:
                page.wait_for_url(lambda url: "authserver/login" not in url, timeout=5000)
                self._log(LogLevel.INFO, "登录成功！页面已跳转。")
            except Exception:
                error_tip = page.locator("#showErrorTip")
                if error_tip.is_visible():
                    error_msg = error_tip.inner_text().strip()
                    if error_msg:
                        browser.close()
                        if "图形动态码错误" in error_msg:
                            raise CaptchaError(f"验证码错误: {error_msg}")
                        if "用户名或者密码有误" in error_msg:
                            raise CredentialError(f"凭据错误: {error_msg}")
                        raise Exception(f"登录失败: {error_msg}")
                if "i.nuist.edu.cn" not in page.url:
                    browser.close()
                    raise Exception(f"未知状态，当前URL: {page.url}")
            cookies = context.cookies()
            browser.close()
            return {item["name"]: item["value"] for item in cookies}
