# Legacy implementations

这里的代码不属于当前运行时主流程，仅用于历史参考：

- `playwright/NuistLogin.py`：旧的用户名/密码、图形验证码 OCR 和 Playwright 浏览器自动化实现，已弃用。
- `poc/passkey_registration_init.py`：早期 Python/fido2 注册 PoC，已弃用。当前注册流程使用根目录的 `browser_passkey.js`。

正式登录入口是根目录的 `login_passkey.py`；兼容旧模块调用的是根目录的 `NuistLogin.py`。不要为主流程安装 Playwright、`ddddocr` 或 `fido2`。
