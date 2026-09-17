# NUIST AuthServer Login

Nuist SSO 一键登录一切校内服务的脚本
> 当然前提要接入CAS

> 已从 playwright 模拟输入账号密码 迁移到了 纯网络层模拟 Passkey 登录。该登录方式无需过二次校验。

## 初次使用

1. 打开 `https://authserver.nuist.edu.cn` 的个人中心/账号安全/生物识别，将`browser_passkey.min.js`粘贴进控制台。
2. 按页面提示完成一次密码验证。
3. 脚本会自动模拟注册一个 Passkey ，并会输出一段 JSON 格式的必要数据。
4. Enjoy.
> 请注意保存与确认凭据安全。Passkey登录无需二次验证手机号 故如凭据泄露请记得及时吊销对应 Passkey。

## 从密码登录迁移到 Passkey

1. 将NuistLogin.py替换为新版
2. 将原传入的密码参数改成 Passkey JSON 文件名（相对路径或绝对路径）即可

## 使用

命令行（只登录 authserver 自身，用于验证凭据可用）：

```bash
python login_passkey.py passkey.local.json
```

作为模块（与旧版 `NuistLogin` 调用方式一致，只把原来的密码参数换成 Passkey bundle）：

```python
from NuistLogin import NuistLogin

cookies = NuistLogin("202xxxxxxxxx", "passkey.local.json", service).login()

# VPN 模式：vpn_cookies 可省略，省略时自动通过 CAS 回调获取，登录后可从
# bot.vpn_cookies 取出缓存下来复用
bot = NuistLogin("202xxxxxxxxx", "passkey.local.json", service, use_vpn=True)
cookies = bot.login()
```

`NuistLogin.py` 也能直接跑：

```bash
python NuistLogin.py 202xxxxxxxxx passkey.local.json [--vpn] [--vpn-cookies vpn_cookies.json]
```

第二个参数可以是 JSON 文件路径、JSON 文本，或已经解析好的 dict。`headless` 仍然接受但不起作用（不启动浏览器）。凭据类失败抛 `CredentialError`，流程类失败抛 `LoginError`，网络层问题抛 `requests` 自身的异常；`CaptchaError` 仅为兼容旧代码保留，不会被抛出。
