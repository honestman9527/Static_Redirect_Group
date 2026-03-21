export default {
  async fetch(request, env) {
    // 处理 CORS 预检请求
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    // 只允许 POST 请求
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    // CSRF 保护: 检查 Origin/Referer
    const origin = request.headers.get("Origin");
    const referer = request.headers.get("Referer");
    const baseDomain = env.BASE_DOMAIN; // 必须配置 BASE_DOMAIN 才能启用此检查

    if (baseDomain) {
      // 允许 localhost 用于调试
      const isLocalhost =
        origin &&
        (origin.includes("localhost") || origin.includes("127.0.0.1"));

      if (!isLocalhost) {
        let valid = false;
        // 检查 Origin
        if (origin && origin.includes(baseDomain)) {
          valid = true;
        }
        // 如果没有 Origin (某些浏览器/场景)，检查 Referer
        else if (!origin && referer && referer.includes(baseDomain)) {
          valid = true;
        }

        if (!valid) {
          return Response.json(
            { error: "CSRF check failed: Invalid Origin/Referer" },
            {
              status: 403,
              headers: { "Access-Control-Allow-Origin": "*" },
            }
          );
        }
      }
    }

      try {
        let pathname,
          url,
          expired_at,
          expire_days,
          turnstile_token,
          verification_proof,
          permanent,
          permanent_password;
        try {
          const body = await request.json();
          pathname = body.pathname;
          url = body.url;
          expired_at = body.expired_at;
          expire_days = body.expire_days;
          turnstile_token = body.turnstile_token;
          verification_proof = body.verification_proof;
          permanent = body.permanent === true;
          permanent_password = body.permanent_password;
        } catch (e) {
          return Response.json(
            { error: "Invalid JSON body" },
            {
              status: 400,
              headers: { "Access-Control-Allow-Origin": "*" },
            }
          );
      }

      const clientIp = request.headers.get("CF-Connecting-IP") || "";
      const verificationWindowSeconds = 5 * 60;

      async function sha256Hex(input) {
        const buffer = await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(input)
        );
        return Array.from(new Uint8Array(buffer))
          .map((byte) => byte.toString(16).padStart(2, "0"))
          .join("");
      }

      async function buildVerificationProof(expiresAtSeconds) {
        return sha256Hex(
          `${env.TURNSTILE_SECRET_KEY}|${clientIp}|${expiresAtSeconds}`
        );
      }

      // 0. 验证 Turnstile token
      const turnstileSecret = env.TURNSTILE_SECRET_KEY;
      let verificationExpiresAt = 0;
      let verificationProof = null;
      if (turnstileSecret) {
        let verified = false;

        if (
          typeof verification_proof === "string" &&
          verification_proof.includes(".")
        ) {
          const [expiresAtRaw, signature] = verification_proof.split(".");
          const expiresAtSeconds = Number(expiresAtRaw);

          if (
            Number.isInteger(expiresAtSeconds) &&
            expiresAtSeconds > Math.floor(Date.now() / 1000)
          ) {
            const expectedSignature = await buildVerificationProof(
              expiresAtSeconds
            );
            if (signature === expectedSignature) {
              verified = true;
              verificationExpiresAt = expiresAtSeconds;
              verificationProof = verification_proof;
            }
          }
        }

        if (!verified) {
          if (!turnstile_token) {
            return Response.json(
              { error: "请完成人机验证" },
              {
                status: 400,
                headers: { "Access-Control-Allow-Origin": "*" },
              }
            );
          }

          const turnstileResponse = await fetch(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            {
              method: "POST",
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
              },
              body: new URLSearchParams({
                secret: turnstileSecret,
                response: turnstile_token,
                remoteip: clientIp,
              }),
            }
          );

          const turnstileResult = await turnstileResponse.json();
          if (!turnstileResult.success) {
            console.error("Turnstile verification failed:", turnstileResult);
            return Response.json(
              { error: "人机验证失败，请重新验证后再试" },
              {
                status: 403,
                headers: { "Access-Control-Allow-Origin": "*" },
              }
            );
          }

          verificationExpiresAt =
            Math.floor(Date.now() / 1000) + verificationWindowSeconds;
          verificationProof = `${verificationExpiresAt}.${await buildVerificationProof(
            verificationExpiresAt
          )}`;
        }

        if (!verificationProof || !verificationExpiresAt) {
          return Response.json(
            { error: "Verification state setup failed" },
            {
              status: 500,
              headers: { "Access-Control-Allow-Origin": "*" },
            }
          );
        }
      }

      function verifiedResponse(payload, init = {}) {
        const responseBody = { ...payload };
        if (verificationProof && verificationExpiresAt) {
          responseBody.verification_proof = verificationProof;
          responseBody.verification_expires_at = verificationExpiresAt;
        }

        return Response.json(responseBody, {
          ...init,
          headers: {
            "Access-Control-Allow-Origin": "*",
            ...(init.headers || {}),
          },
        });
      }

      // 1. 验证输入
      if (typeof pathname !== "string") {
        pathname = "";
      }
      pathname = pathname.trim();

      if (pathname && (pathname.length < 5 || pathname.length > 10)) {
        return verifiedResponse(
          { error: "Invalid pathname (5-10 chars)" },
          { status: 400 }
        );
      }
      // 简单正则验证 pathname 是否只包含允许字符
      if (pathname && !/^[a-zA-Z0-9_-]+$/.test(pathname)) {
        return verifiedResponse(
          { error: "Invalid characters in pathname" },
          { status: 400 }
        );
      }

      if (!url || typeof url !== "string" || url.length > 300) {
        return verifiedResponse(
          { error: "Invalid URL (max 300 chars)" },
          { status: 400 }
        );
      }
      try {
        const parsedUrl = new URL(url); // 验证 URL 格式
        // 安全检查: 必须是 http 或 https 协议
        if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
          return verifiedResponse(
            { error: "Invalid URL protocol (only http/https allowed)" },
            { status: 400 }
          );
        }

        // 严格字符检查: 禁止 Emoji 和非打印字符 (只允许 ASCII 可打印字符)
        // 范围: 0x21-0x7E (标准 ASCII 符号、数字、字母)
        // 但 URL 可能包含百分号编码，所以我们检查是否包含非 ASCII 字符
        // eslint-disable-next-line no-control-regex
        if (/[^\x00-\x7F]/.test(url)) {
          return verifiedResponse(
            {
              error:
                "URL contains non-ASCII characters (Emoji/Unicode not allowed)",
            },
            { status: 400 }
          );
        }

        // 检查是否指向自身 (循环重定向保护)
        const baseDomain = env.BASE_DOMAIN || "";
        if (baseDomain) {
          // 忽略大小写比较
          if (parsedUrl.hostname.toLowerCase() === baseDomain.toLowerCase()) {
            return verifiedResponse(
              {
                error:
                  "Cannot redirect to the URL shortener itself (Loop protection)",
              },
              { status: 400 }
            );
          }
        }
      } catch (e) {
        return verifiedResponse({ error: "Invalid URL format" }, { status: 400 });
      }

      // 验证 URL 安全性 (通过 Cloudflare Family DNS)
      // 我们通过 DoH (DNS over HTTPS) 查询域名
      // 如果域名被 Cloudflare Family DNS (1.1.1.3) 拦截（通常解析为 0.0.0.0 或 ::），则说明是不安全/成人内容
      try {
        const parsedUrlForDns = new URL(url);
        const hostname = parsedUrlForDns.hostname;
        // 排除 IP 地址 (简单的正则，非严谨)
        const isIp =
          /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":");

        if (!isIp) {
          // 使用域名 endpoint，避免 IP 证书验证问题
          const dohUrl = `https://family.cloudflare-dns.com/dns-query?name=${encodeURIComponent(
            hostname
          )}&type=A`;
          console.log("DoH Request:", dohUrl);

          const dohResp = await fetch(dohUrl, {
            headers: { Accept: "application/dns-json" },
          });

          console.log("DoH Status:", dohResp.status);

          if (dohResp.ok) {
            const dnsData = await dohResp.json();
            console.log("DoH Response Body:", JSON.stringify(dnsData));

            // 检查 Answer
            if (dnsData.Answer) {
              for (const answer of dnsData.Answer) {
                // Cloudflare Family DNS 拦截的域名通常解析到 0.0.0.0 或 ::
                if (answer.data === "0.0.0.0" || answer.data === "::") {
                  const reason = dnsData.Comment
                    ? dnsData.Comment.join(", ")
                    : "Malware/Adult Content";
                  return verifiedResponse(
                    {
                      error: `URL blocked by Cloudflare Family DNS: ${reason}`,
                    },
                    { status: 400 }
                  );
                }
              }
            } else {
              // 如果没有 Answer (NXDOMAIN 等)，可能域名不存在
              // 但 DoH 有时对 CNAME 处理不同，这里我们主要关注拦截
              // 如果用户输入了不存在的域名，虽然不能访问，但不算安全风险
            }
          }
        }
      } catch (e) {
        console.error("DNS Safety Check Error:", e);
        // 调试模式：如果 DNS 检查出错，返回错误信息而不是静默放行
        // 生产环境通常选择 fail-open (放行) 以保证可用性，但为了排查问题，这里改为 fail-closed
        return verifiedResponse(
          {
            error:
              "Security check failed: Unable to verify URL safety (" +
              e.message +
              ")",
          },
          { status: 500 }
        );
      }

      let expiredAtISO = "";
      if (permanent) {
        const permanentPassword = env.PERMANENT_LINK_PASSWORD;

        if (!permanentPassword) {
          return verifiedResponse(
            { error: "Server configuration error: permanent password not set" },
            { status: 500 }
          );
        }

        if (
          typeof permanent_password !== "string" ||
          permanent_password !== permanentPassword
        ) {
          return verifiedResponse(
            { error: "长期短链密码验证失败" },
            { status: 403 }
          );
        }
      } else {
        if (!Number.isInteger(expire_days) || expire_days < 1 || expire_days > 7) {
          return verifiedResponse(
            { error: "Expiration days must be an integer between 1 and 7" },
            { status: 400 }
          );
        }

        // 2. 准备数据
        // 将 Unix 时间戳转换为 ISO 8601 字符串
        const expiredDate = new Date(Date.now() + expire_days * 24 * 3600 * 1000);
        const now = new Date();
        if (isNaN(expiredDate.getTime())) {
          return verifiedResponse({ error: "Invalid timestamp" }, { status: 400 });
        }

        // 检查有效期是否超过 7 天
        const diffTime = expiredDate.getTime() - now.getTime();
        const diffDays = diffTime / (1000 * 3600 * 24);
        if (diffDays > 7) {
          return verifiedResponse(
            { error: "Expiration date cannot exceed 7 days from now" },
            { status: 400 }
          );
        }
        // 检查有效期是否在过去
        if (diffTime <= 0) {
          return verifiedResponse(
            { error: "Expiration date must be in the future" },
            { status: 400 }
          );
        }

        expiredAtISO = expiredDate.toISOString();
      }

      // 3. 获取 GitHub 文件
      const owner = env.GITHUB_OWNER; // 需要在 Worker 环境变量中设置
      const repo = env.GITHUB_REPO; // 需要在 Worker 环境变量中设置
      const branch = env.GITHUB_BRANCH || "main";
      const filePath = "js/rules_intermediate.js";
      const directFilePath = "js/rules_direct.js";
      const token = env.GITHUB_TOKEN;

      if (!token || !owner || !repo) {
        return verifiedResponse({ error: "Server configuration error" }, { status: 500 });
      }

      async function fetchGitHubFile(targetPath) {
        const getUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${targetPath}?ref=${branch}`;

        const response = await fetch(getUrl, {
          headers: {
            Authorization: `Bearer ${token}`,
            "User-Agent": "Cloudflare-Worker",
            Accept: "application/vnd.github.v3+json",
          },
        });

        if (!response.ok) {
          const errText = await response.text();
          console.error("GitHub Fetch Error:", errText);
          throw new Error(
            `Failed to fetch file from GitHub: ${response.status} (${targetPath})`
          );
        }

        return response.json();
      }

      function decodeGitHubContent(fileData) {
        const binaryString = atob(fileData.content.replace(/\s/g, ""));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        return new TextDecoder("utf-8").decode(bytes);
      }

      function parseRulesContent(content) {
        const jsonStart = content.indexOf("{");
        const jsonEnd = content.lastIndexOf("}");

        if (jsonStart === -1 || jsonEnd === -1) {
          throw new Error("Failed to parse file content");
        }

        const jsonStr = content.substring(jsonStart, jsonEnd + 1);
        return JSON.parse(jsonStr);
      }

      function generateRandomPathname(length = 6) {
        const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        let result = "";
        const randomValues = crypto.getRandomValues(new Uint8Array(length));
        for (let i = 0; i < length; i++) {
          result += chars[randomValues[i] % chars.length];
        }
        return result;
      }

      let fileData;
      let directFileData;
      try {
        [fileData, directFileData] = await Promise.all([
          fetchGitHubFile(filePath),
          fetchGitHubFile(directFilePath),
        ]);
      } catch (error) {
        return verifiedResponse({ error: error.message }, { status: 502 });
      }

      // 4. 解析并更新内容
      // 正确处理 UTF-8 解码: Base64 -> Uint8Array -> String
      const content = decodeGitHubContent(fileData);
      const directContent = decodeGitHubContent(directFileData);
      const sha = fileData.sha;
      let rules;
      let directRules;
      try {
        rules = parseRulesContent(content);
        directRules = parseRulesContent(directContent);
      } catch (e) {
        return verifiedResponse({ error: "File content is not valid JSON" }, { status: 500 });
      }

      // 检查是否已存在；若未填写则自动生成一个可用路径
      let finalPathname = pathname;
      let pathKey = "";

      if (!finalPathname) {
        let attempts = 0;
        do {
          finalPathname = generateRandomPathname();
          pathKey = "/" + finalPathname;
          attempts += 1;
        } while ((rules[pathKey] || directRules[pathKey]) && attempts < 20);

        if (!pathKey || rules[pathKey] || directRules[pathKey]) {
          return verifiedResponse(
            { error: "Failed to generate an available pathname" },
            { status: 500 }
          );
        }
      } else {
        pathKey = "/" + finalPathname;
        if (rules[pathKey] || directRules[pathKey]) {
          return verifiedResponse(
            { error: "Pathname already exists" },
            { status: 409 }
          );
        }
      }

      // 添加新规则
      rules[pathKey] = {
        url: url,
        expired_at: expiredAtISO,
      };

      // 5. 序列化并提交
      const newJsonStr = JSON.stringify(rules, null, 4);
      const newContent = `window.RULES_INTERMEDIATE = ${newJsonStr};\n`;

      // 正确处理 UTF-8 编码: String -> Uint8Array -> Base64
      const encoder = new TextEncoder();
      const data = encoder.encode(newContent);
      let binary = "";
      const len = data.byteLength;
      for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(data[i]);
      }
      const finalBase64 = btoa(binary);

      const putUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}`;
      const commitMessage = `Add short link: ${finalPathname}`;

      const putResp = await fetch(putUrl, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "User-Agent": "Cloudflare-Worker",
          Accept: "application/vnd.github.v3+json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: commitMessage,
          content: finalBase64,
          sha: sha,
          branch: branch,
        }),
      });

      if (!putResp.ok) {
        const errText = await putResp.text();
        console.error("GitHub API Error:", errText);
        return verifiedResponse({ error: "Failed to commit to GitHub" }, { status: 502 });
      }

      // 构建返回的短链 URL
      const baseDomain = env.BASE_DOMAIN || "";
      const shortUrl = baseDomain ? `https://${baseDomain}/${finalPathname}` : null; // 如果后端没配，前端自己拼

      const putRespData = await putResp.json();

      // 返回 Commit URL 方便前端跳转
      // 优先使用 commit.sha，如果没有则使用 content.sha，最后回退到 main
      // GitHub API Response Structure for PUT /contents/:
      // { "content": { "name": "...", "sha": "BLOB_SHA" }, "commit": { "sha": "COMMIT_SHA", ... } }
      const commitSha = putRespData.commit
        ? putRespData.commit.sha
        : putRespData.content
        ? putRespData.content.sha
        : "main";
      const commitUrl = `https://github.com/${owner}/${repo}/commit/${commitSha}`;

      return verifiedResponse({
        success: true,
        message: "Short link created",
        short_url: shortUrl,
        commit_url: commitUrl,
      });
    } catch (err) {
      console.error(err);
      return verifiedResponse(
        { error: "Internal Server Error: " + err.message },
        { status: 500 }
      );
    }
  },
};
