(() => {
  "use strict";

  /*
   * NUIST 软件通行密钥注册脚本
   *
   * 流程：
   *   1. GET /personalInfo/common/isUserRecheckNecessary
   *        code === "0"          -> 无需二次验证，直接进入注册。
   *        其它（如 2106010002）  -> 二次验证已失效/需要验证。
   *   2. 需要二次验证时：直接模拟点击页面上的“绑定当前设备”，触发学校原生的
   *      “身份验证”流程（登录密码 + 图形动态码），由页面自己完成真实校验。校验
   *      通过后页面有两种走法，脚本把两者都当作放行信号：
   *        a. 请求 /accountSecurity/isDeviceBinded -> 中止该请求，丢弃响应。
   *        b. 不请求 a，直接弹出“绑定当前设备”设备名称录入框 -> 关闭该模态框。
   *      两种方式都会掐断浏览器原生的添加流程。
   *   3. 收到该信号后，由脚本自己 POST startRegister -> 本地生成 ES256 软件凭据
   *      -> POST finishRegister。凭据与提交体的构造与 legacy/poc/passkey_registration_init.py 的早期 PoC 保持兼容。
   *
   * 安全提示：脚本会在浏览器内生成并短暂持有一份可用于身份认证的私钥，
   * 私钥仅输出一次（控制台 + 尽力复制到剪贴板）。请妥善保存，泄露后任何
   * 获得该私钥的人都可能冒用此通行密钥。
   */

  const CONFIG = Object.freeze({
    allowedOrigin: "https://authserver.nuist.edu.cn",
    apiBase: "/personalInfo",
    isUserRecheckNecessaryPath: "/common/isUserRecheckNecessary",
    isDeviceBindedMarker: "/accountSecurity/isDeviceBinded",
    bindModalTitle: "绑定当前设备",
    startRegisterPath: "/accountSecurity/startRegister",
    finishRegisterPath: "/accountSecurity/finishRegister",
    credentialIdLength: 16,
    deviceName: "Simulated-Virtual-Device",
    finishExtraN: "0.9239225681951135",
    verifyWaitTimeoutMs: 10 * 60 * 1000,
  });

  const utf8 = new TextEncoder();

  // ---------- 字节 / Base64url / PEM / CBOR 工具 ----------

  const asBytes = (value) => {
    if (value instanceof Uint8Array) return new Uint8Array(value);
    if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
    }
    if (typeof value === "string") return base64urlDecode(value);
    throw new TypeError("无法将该值转换为字节数组");
  };

  const concatBytes = (...parts) => {
    const arrays = parts.map(asBytes);
    const result = new Uint8Array(arrays.reduce((sum, part) => sum + part.length, 0));
    let offset = 0;
    for (const part of arrays) {
      result.set(part, offset);
      offset += part.length;
    }
    return result;
  };

  const base64urlEncode = (value) => {
    const bytes = asBytes(value);
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
  };

  const base64urlToBase64 = (value) => {
    const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
    return normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  };

  const base64urlDecode = (value) => {
    const binary = atob(base64urlToBase64(value));
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  };

  const pemEncode = (label, value) => {
    const base64 = base64urlToBase64(base64urlEncode(value));
    const lines = base64.match(/.{1,64}/g) ?? [];
    return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
  };

  const cborHead = (majorType, length) => {
    if (!Number.isInteger(length) || length < 0 || length > 0xff) {
      throw new TypeError("CBOR 长度超出当前编码器范围");
    }
    return length < 24
      ? Uint8Array.of((majorType << 5) | length)
      : Uint8Array.of((majorType << 5) | 24, length);
  };

  function cborEncode(value) {
    if (Number.isInteger(value)) {
      return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
    }
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
      const bytes = asBytes(value);
      return concatBytes(cborHead(2, bytes.length), bytes);
    }
    if (typeof value === "string") {
      const bytes = utf8.encode(value);
      return concatBytes(cborHead(3, bytes.length), bytes);
    }
    if (value instanceof Map) {
      const entries = [...value.entries()];
      return concatBytes(
        cborHead(5, entries.length),
        ...entries.flatMap(([key, item]) => [cborEncode(key), cborEncode(item)]),
      );
    }
    throw new TypeError(`不支持的 CBOR 类型：${typeof value}`);
  }

  // ---------- 网络请求（脚本自己发起，不复用页面的 Vuex action） ----------

  async function apiFetch(path, method, body) {
    const init = {
      method,
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "X-Requested-With": "XMLHttpRequest",
      },
    };
    if (method !== "GET") init.body = JSON.stringify(body ?? {});
    const response = await fetch(CONFIG.apiBase + path, init);
    if (!response.ok) throw new Error(`${path} 返回 HTTP ${response.status}`);
    try {
      return await response.json();
    } catch (_) {
      throw new Error(`${path} 返回了无法解析的响应`);
    }
  }

  const isBusinessSuccess = (body) => String(body?.code ?? "") === "0";

  // ---------- 软件凭据生成（构造方式与 init.py 保持一致） ----------

  async function createSoftwareCredential(publicKeyOptions) {
    if (!publicKeyOptions || typeof publicKeyOptions !== "object") {
      throw new TypeError("startRegister 未返回有效的 PublicKeyCredentialCreationOptions");
    }

    const rpId = publicKeyOptions.rp?.id || location.hostname;
    const origin = `https://${rpId}`;
    const challenge = base64urlEncode(asBytes(publicKeyOptions.challenge));

    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const [publicJwk, privatePkcs8] = await Promise.all([
      crypto.subtle.exportKey("jwk", keyPair.publicKey),
      crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
    ]);

    const credentialId = crypto.getRandomValues(new Uint8Array(CONFIG.credentialIdLength));
    const credentialIdBase64url = base64urlEncode(credentialId);
    const x = base64urlDecode(publicJwk.x);
    const y = base64urlDecode(publicJwk.y);
    if (x.length !== 32 || y.length !== 32) throw new Error("生成的 P-256 公钥坐标长度异常");

    // COSE ES256 公钥（与 init.py 的 ES256.from_cryptography_key 等价）。
    const cosePublicKey = cborEncode(new Map([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, x],
      [-3, y],
    ]));
    const authenticatorData = await buildAuthenticatorData(rpId, credentialId, cosePublicKey);

    const clientData = {
      type: "webauthn.create",
      challenge,
      origin,
      crossOrigin: false,
    };
    const clientDataJSON = utf8.encode(JSON.stringify(clientData));
    const attestationObject = cborEncode(new Map([
      ["fmt", "none"],
      ["attStmt", new Map()],
      ["authData", authenticatorData],
    ]));

    const credentialForServer = {
      type: "public-key",
      id: credentialIdBase64url,
      response: {
        attestationObject: base64urlEncode(attestationObject),
        clientDataJSON: base64urlEncode(clientDataJSON),
      },
      clientExtensionResults: {},
    };

    const bundle = {
      rpId,
      credentialId: credentialIdBase64url,
      privateKeyPkcs8Pem: pemEncode("PRIVATE KEY", privatePkcs8),
    };

    return { credentialForServer, bundle };
  }

  const buildAuthenticatorData = async (rpId, credentialId, cosePublicKey) => {
    const rpIdHash = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(rpId)));
    const credentialIdLength = Uint8Array.of(
      (credentialId.length >>> 8) & 0xff,
      credentialId.length & 0xff,
    );
    return concatBytes(
      rpIdHash,
      Uint8Array.of(0x41), // UP + AT
      new Uint8Array(4), // sign counter
      new Uint8Array(16), // AAGUID
      credentialIdLength,
      credentialId,
      cosePublicKey,
    );
  };

  // ---------- 等待放行信号：isDeviceBinded 请求，或“绑定当前设备”模态框 ----------

  // 页面原生的设备名称录入框。它出现就代表二次验证已通过、进入了原生创建流程。
  // 必须排除还没显示出来的模态框：iView 可能提前把节点挂进 DOM，只判断“存在”会误判。
  const isVisible = (element) =>
    typeof element.checkVisibility === "function"
      ? element.checkVisibility({ visibilityProperty: true })
      : element.getClientRects().length > 0;

  function findBindModal() {
    for (const modal of document.querySelectorAll(".ivu-modal")) {
      const label = modal.querySelector(".ivu-modal-header label");
      if (label?.textContent.trim() !== CONFIG.bindModalTitle) continue;
      if (isVisible(modal)) return modal;
    }
    return null;
  }

  // 优先走页面自己的关闭逻辑，直接摘 DOM 会留下遮罩层和被锁住的滚动条。
  function dismissBindModal(modal) {
    const closer =
      modal.querySelector(".ivu-modal-footer button[title='取消']") ||
      modal.querySelector(".base-modal-close, .ivu-modal-close");
    if (closer) {
      closer.click();
      return;
    }
    (modal.closest(".ivu-modal-wrap") || modal).remove();
  }

  function waitForBindSignal(timeoutMs) {
    return new Promise((resolve, reject) => {
      const originalOpen = XMLHttpRequest.prototype.open;
      const originalSend = XMLHttpRequest.prototype.send;
      let settled = false;
      let observer = null;
      const timer = setTimeout(
        () => finish(new Error("等待原生身份验证放行信号超时，请重新运行脚本")),
        timeoutMs,
      );

      const cleanup = () => {
        XMLHttpRequest.prototype.open = originalOpen;
        XMLHttpRequest.prototype.send = originalSend;
        observer?.disconnect();
        clearTimeout(timer);
      };
      const finish = (error) => {
        if (settled) return;
        settled = true;
        cleanup();
        error ? reject(error) : resolve();
      };

      // 信号一：拦截 isDeviceBinded 请求，丢弃响应并中止原生添加流程。
      XMLHttpRequest.prototype.open = function (method, url, ...rest) {
        this.__nuistUrl = String(url);
        return originalOpen.call(this, method, url, ...rest);
      };
      XMLHttpRequest.prototype.send = function (...args) {
        if (!this.__nuistUrl?.includes(CONFIG.isDeviceBindedMarker)) {
          return originalSend.apply(this, args);
        }
        finish();
        this.abort();
      };

      // 信号二（兜底）：页面有时不请求 isDeviceBinded，而是直接弹出设备名称录入框。
      const checkBindModal = () => {
        if (settled) return;
        const modal = findBindModal();
        if (!modal) return;
        dismissBindModal(modal);
        finish();
      };
      // 连 style/class 一起监听：模态框可能先挂载再显示，只看 childList 会漏掉显示那一刻。
      // 这里不做一次立即检查：监听在点击之前就装好了，点击之后出现的都能抓到；
      // 而运行脚本前页面上残留的同名模态框不代表验证已通过，扫到了反而会提前放行。
      observer = new MutationObserver(checkBindModal);
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["style", "class"],
      });
    });
  }

  // 定位页面上的“绑定当前设备”入口。
  function findBindButton() {
    const direct = document.querySelector(".account-item.add_item");
    if (direct) return direct;
    for (const span of document.querySelectorAll("span")) {
      if (span.textContent.trim() === "绑定当前设备") {
        return span.closest(".account-item") || span.parentElement;
      }
    }
    return null;
  }

  async function ensureVerified() {
    const status = await apiFetch(CONFIG.isUserRecheckNecessaryPath, "GET");
    if (isBusinessSuccess(status)) return; // code "0"：无需二次验证。

    const bindButton = findBindButton();
    if (!bindButton) {
      throw new Error('未找到“绑定当前设备”入口，请打开“账户安全-通行密钥”页面后重试');
    }

    // 先装好监听，再模拟点击“绑定当前设备”触发页面原生流程（含真实的身份验证）。
    // 验证通过后页面要么请求 isDeviceBinded，要么直接弹出设备名称录入框，
    // 两者都算放行信号；脚本收到后掐断原生添加流程，转由自己完成注册。
    const waitPromise = waitForBindSignal(CONFIG.verifyWaitTimeoutMs);
    bindButton.click();
    await waitPromise;
  }

  // ---------- 注册接口 ----------

  async function performStartRegister() {
    const response = await apiFetch(CONFIG.startRegisterPath, "POST", {});
    if (!response?.datas?.request?.publicKeyCredentialCreationOptions) {
      throw new Error(`startRegister 失败：${response?.message || "服务器未返回注册参数"}`);
    }
    return response.datas.request;
  }

  function createFinishBody(request, credentialForServer) {
    return {
      deviceName: CONFIG.deviceName,
      anonbiometricsd: null,
      response: JSON.stringify({
        requestId: request.requestId,
        credential: credentialForServer,
        sessionToken: null,
      }),
      n: CONFIG.finishExtraN,
    };
  }

  async function performFinishRegister(request, credentialForServer) {
    const response = await apiFetch(
      CONFIG.finishRegisterPath,
      "POST",
      createFinishBody(request, credentialForServer),
    );
    if (!isBusinessSuccess(response)) {
      throw new Error(`finishRegister 失败：${response?.message || "服务器拒绝了注册请求"}`);
    }
    return response;
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      const textArea = document.createElement("textarea");
      try {
        textArea.value = text;
        textArea.style.cssText = "position:fixed;opacity:0;pointer-events:none";
        document.body.appendChild(textArea);
        textArea.select();
        return document.execCommand("copy");
      } catch (_) {
        return false;
      } finally {
        textArea.remove();
      }
    }
  }

  // ---------- 主流程 ----------

  function assertEnvironment() {
    if (location.origin !== CONFIG.allowedOrigin) {
      throw new Error(`请在 ${CONFIG.allowedOrigin} 的个人中心页面运行此脚本`);
    }
    if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) {
      throw new Error("当前页面不是支持 Web Crypto 的安全上下文");
    }
    if (globalThis.__NUIST_SOFTWARE_PASSKEY_RUNNING__) {
      throw new Error("脚本已经在等待流程完成，请勿重复运行");
    }
  }

  async function registerPasskey() {
    await ensureVerified();
    const request = await performStartRegister();
    const { credentialForServer, bundle } = await createSoftwareCredential(
      request.publicKeyCredentialCreationOptions,
    );
    const finishResponse = await performFinishRegister(request, credentialForServer);
    const userId = finishResponse?.datas?.result;
    const anonbiometricsd = finishResponse?.datas?.anonbiometricsd;
    if (typeof userId !== "string" || !userId || typeof anonbiometricsd !== "string" || !anonbiometricsd) {
      throw new Error("finishRegister 成功，但响应中缺少 userId 或 anonbiometricsd，已停止导出凭据");
    }

    // 这两个值分别用于 startAssertion 的 userId 和 id；必须与私钥一起保存。
    return { ...bundle, userId, anonbiometricsd };
  }

  async function publishBundle(bundle) {
    const exported = JSON.stringify(bundle, null, 2);
    console.log(`[NUIST 软件通行密钥｜仅输出一次]\n${exported}`);
    const copied = await copyText(exported);
    alert(
      copied
        ? "软件通行密钥已注册，私钥包已输出到控制台并复制到剪切板。请立即保存到安全位置；任何获得该内容的人都可能冒用此通行密钥。保存后请清理剪切板。"
        : "软件通行密钥已注册，私钥包已输出到控制台，但浏览器拒绝了剪切板写入。请从控制台手动复制并妥善保存；任何获得该内容的人都可能冒用此通行密钥。",
    );
  }

  async function run() {
    assertEnvironment();
    globalThis.__NUIST_SOFTWARE_PASSKEY_RUNNING__ = true;
    try {
      await publishBundle(await registerPasskey());
    } finally {
      delete globalThis.__NUIST_SOFTWARE_PASSKEY_RUNNING__;
    }
  }

  run().catch((error) => {
    console.error("[NUIST 软件通行密钥] 执行失败：", error);
    alert(`软件通行密钥生成失败：${error?.message || String(error)}\n\n请根据页面提示处理后重新运行脚本。`);
  });
})();
