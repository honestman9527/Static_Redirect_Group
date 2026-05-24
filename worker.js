const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

const RULE_FILES = {
  intermediate: {
    filePath: "js/rules_intermediate.js",
    varName: "RULES_INTERMEDIATE",
  },
  direct: {
    filePath: "js/rules_direct.js",
    varName: "RULES_DIRECT",
  },
};

class HttpError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const requestUrl = new URL(request.url);
    const isAdminRoute = requestUrl.pathname.startsWith("/api/admin/");

    try {
      if (isAdminRoute) {
        return await handleAdminRequest(request, env, requestUrl);
      }

      if (request.method !== "POST") {
        return new Response("Method not allowed", {
          status: 405,
          headers: CORS_HEADERS,
        });
      }

      const csrfResponse = validateCsrf(request, env);
      if (csrfResponse) return csrfResponse;

      return await handleCreateRequest(request, env);
    } catch (err) {
      console.error(err);

      if (err instanceof HttpError) {
        return jsonResponse({ error: err.message }, { status: err.status });
      }

      return jsonResponse(
        { error: "Internal Server Error: " + err.message },
        { status: 500 }
      );
    }
  },
};

function jsonResponse(payload, init = {}) {
  return Response.json(payload, {
    ...init,
    headers: {
      ...CORS_HEADERS,
      ...(init.headers || {}),
    },
  });
}

function methodNotAllowed() {
  return new Response("Method not allowed", {
    status: 405,
    headers: CORS_HEADERS,
  });
}

function validateCsrf(request, env) {
  const baseDomain = env.BASE_DOMAIN;
  if (!baseDomain) return null;

  const origin = request.headers.get("Origin");
  const referer = request.headers.get("Referer");
  const isLocalhost =
    origin && (origin.includes("localhost") || origin.includes("127.0.0.1"));

  if (isLocalhost) return null;

  if (origin && origin.includes(baseDomain)) return null;
  if (!origin && referer && referer.includes(baseDomain)) return null;

  return jsonResponse(
    { error: "CSRF check failed: Invalid Origin/Referer" },
    { status: 403 }
  );
}

async function readJsonBody(request) {
  try {
    return await request.json();
  } catch (err) {
    throw new HttpError("Invalid JSON body", 400);
  }
}

async function sha256Hex(input) {
  const buffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input)
  );
  return bytesToHex(new Uint8Array(buffer));
}

async function hmacSha256Hex(secret, input) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(input)
  );
  return bytesToHex(new Uint8Array(signature));
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function constantTimeEqual(a, b) {
  const aBytes = new TextEncoder().encode(String(a || ""));
  const bBytes = new TextEncoder().encode(String(b || ""));
  const maxLength = Math.max(aBytes.length, bBytes.length);
  let diff = aBytes.length ^ bBytes.length;

  for (let i = 0; i < maxLength; i += 1) {
    diff |= (aBytes[i] || 0) ^ (bBytes[i] || 0);
  }

  return diff === 0;
}

async function secretMatches(input, secret) {
  if (typeof input !== "string" || typeof secret !== "string") return false;
  const [inputHash, secretHash] = await Promise.all([
    sha256Hex(input),
    sha256Hex(secret),
  ]);
  return constantTimeEqual(inputHash, secretHash);
}

function normalizePathname(value, { minLength, maxLength }) {
  let pathname = typeof value === "string" ? value.trim() : "";
  if (pathname.startsWith("/")) pathname = pathname.slice(1);

  if (!pathname) return "";

  if (pathname.length < minLength || pathname.length > maxLength) {
    throw new HttpError(
      `Invalid pathname (${minLength}-${maxLength} chars)`,
      400
    );
  }

  if (!/^[a-zA-Z0-9_-]+$/.test(pathname)) {
    throw new HttpError("Invalid characters in pathname", 400);
  }

  if (["api", "js", "_url"].includes(pathname.toLowerCase())) {
    throw new HttpError("Pathname is reserved", 400);
  }

  return pathname;
}

function validateTargetUrl(url, env) {
  if (!url || typeof url !== "string" || url.length > 300) {
    throw new HttpError("Invalid URL (max 300 chars)", 400);
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (err) {
    throw new HttpError("Invalid URL format", 400);
  }

  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new HttpError("Invalid URL protocol (only http/https allowed)", 400);
  }

  if (/[^\x00-\x7F]/.test(url)) {
    throw new HttpError(
      "URL contains non-ASCII characters (Emoji/Unicode not allowed)",
      400
    );
  }

  const baseDomain = env.BASE_DOMAIN || "";
  if (baseDomain && parsedUrl.hostname.toLowerCase() === baseDomain.toLowerCase()) {
    throw new HttpError(
      "Cannot redirect to the URL shortener itself (Loop protection)",
      400
    );
  }
}

async function verifyUrlSafety(url) {
  try {
    const parsedUrlForDns = new URL(url);
    const hostname = parsedUrlForDns.hostname;
    const isIp =
      /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":");

    if (isIp) return;

    const dohUrl = `https://family.cloudflare-dns.com/dns-query?name=${encodeURIComponent(
      hostname
    )}&type=A`;
    console.log("DoH Request:", dohUrl);

    const dohResp = await fetch(dohUrl, {
      headers: { Accept: "application/dns-json" },
    });

    console.log("DoH Status:", dohResp.status);

    if (!dohResp.ok) return;

    const dnsData = await dohResp.json();
    console.log("DoH Response Body:", JSON.stringify(dnsData));

    if (!dnsData.Answer) return;

    for (const answer of dnsData.Answer) {
      if (answer.data === "0.0.0.0" || answer.data === "::") {
        const reason = dnsData.Comment
          ? dnsData.Comment.join(", ")
          : "Malware/Adult Content";
        throw new HttpError(
          `URL blocked by Cloudflare Family DNS: ${reason}`,
          400
        );
      }
    }
  } catch (err) {
    if (err instanceof HttpError) throw err;

    console.error("DNS Safety Check Error:", err);
    throw new HttpError(
      "Security check failed: Unable to verify URL safety (" + err.message + ")",
      500
    );
  }
}

function getGitHubConfig(env) {
  const owner = env.GITHUB_OWNER;
  const repo = env.GITHUB_REPO;
  const branch = env.GITHUB_BRANCH || "main";
  const token = env.GITHUB_TOKEN;

  if (!token || !owner || !repo) {
    throw new HttpError("Server configuration error", 500);
  }

  return { owner, repo, branch, token };
}

async function fetchGitHubFile(env, targetPath) {
  const { owner, repo, branch, token } = getGitHubConfig(env);
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
    throw new HttpError(
      `Failed to fetch file from GitHub: ${response.status} (${targetPath})`,
      502
    );
  }

  return response.json();
}

function decodeGitHubContent(fileData) {
  const binaryString = atob(fileData.content.replace(/\s/g, ""));
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i += 1) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return new TextDecoder("utf-8").decode(bytes);
}

function encodeGitHubContent(content) {
  const data = new TextEncoder().encode(content);
  let binary = "";
  for (let i = 0; i < data.byteLength; i += 1) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary);
}

function parseRulesContent(content) {
  const jsonStart = content.indexOf("{");
  const jsonEnd = content.lastIndexOf("}");

  if (jsonStart === -1 || jsonEnd === -1) {
    throw new HttpError("Failed to parse file content", 500);
  }

  const jsonStr = content
    .substring(jsonStart, jsonEnd + 1)
    .replace(/,\s*([}\]])/g, "$1");

  try {
    return JSON.parse(jsonStr);
  } catch (err) {
    throw new HttpError("File content is not valid JSON", 500);
  }
}

async function readRulesFile(env, type) {
  const ruleFile = RULE_FILES[type];
  const fileData = await fetchGitHubFile(env, ruleFile.filePath);
  const content = decodeGitHubContent(fileData);
  const rules = parseRulesContent(content);

  return {
    ...ruleFile,
    sha: fileData.sha,
    rules,
  };
}

async function writeRulesFile(env, ruleFile, rules, commitMessage) {
  const { owner, repo, branch, token } = getGitHubConfig(env);
  const newJsonStr = JSON.stringify(rules, null, 4);
  const newContent = `window.${ruleFile.varName} = ${newJsonStr};\n`;
  const putUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${ruleFile.filePath}`;

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
      content: encodeGitHubContent(newContent),
      sha: ruleFile.sha,
      branch,
    }),
  });

  if (!putResp.ok) {
    const errText = await putResp.text();
    console.error("GitHub API Error:", errText);
    throw new HttpError("Failed to commit to GitHub", 502);
  }

  return putResp.json();
}

function getRuleData(ruleValue) {
  if (typeof ruleValue === "string") {
    return { url: ruleValue };
  }

  if (typeof ruleValue === "object" && ruleValue !== null) {
    return ruleValue;
  }

  return null;
}

function generateRandomPathname(length = 6) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  const randomValues = crypto.getRandomValues(new Uint8Array(length));
  for (let i = 0; i < length; i += 1) {
    result += chars[randomValues[i] % chars.length];
  }
  return result;
}

function buildShortUrl(env, pathname) {
  const baseDomain = env.BASE_DOMAIN || "";
  return baseDomain ? `https://${baseDomain}/${pathname}` : null;
}

function buildCommitUrl(env, putRespData) {
  const owner = env.GITHUB_OWNER;
  const repo = env.GITHUB_REPO;
  const commitSha = putRespData.commit
    ? putRespData.commit.sha
    : putRespData.content
    ? putRespData.content.sha
    : "main";
  return `https://github.com/${owner}/${repo}/commit/${commitSha}`;
}

async function handleCreateRequest(request, env) {
  let verificationProof = null;
  let verificationExpiresAt = 0;

  function verifiedResponse(payload, init = {}) {
    const responseBody = { ...payload };
    if (verificationProof && verificationExpiresAt) {
      responseBody.verification_proof = verificationProof;
      responseBody.verification_expires_at = verificationExpiresAt;
    }

    return jsonResponse(responseBody, init);
  }

  try {
    const body = await readJsonBody(request);
    let pathname = body.pathname;
    const url = body.url;
    const expireDays = body.expire_days;
    const turnstileToken = body.turnstile_token;
    const proofFromRequest = body.verification_proof;
    const permanent = body.permanent === true;
    const permanentPassword = body.permanent_password;

    const clientIp = request.headers.get("CF-Connecting-IP") || "";
    const verificationWindowSeconds = 5 * 60;

    async function buildVerificationProof(expiresAtSeconds) {
      return sha256Hex(
        `${env.TURNSTILE_SECRET_KEY}|${clientIp}|${expiresAtSeconds}`
      );
    }

    const turnstileSecret = env.TURNSTILE_SECRET_KEY;
    if (turnstileSecret) {
      let verified = false;

      if (typeof proofFromRequest === "string" && proofFromRequest.includes(".")) {
        const [expiresAtRaw, signature] = proofFromRequest.split(".");
        const expiresAtSeconds = Number(expiresAtRaw);

        if (
          Number.isInteger(expiresAtSeconds) &&
          expiresAtSeconds > Math.floor(Date.now() / 1000)
        ) {
          const expectedSignature = await buildVerificationProof(expiresAtSeconds);
          if (constantTimeEqual(signature, expectedSignature)) {
            verified = true;
            verificationExpiresAt = expiresAtSeconds;
            verificationProof = proofFromRequest;
          }
        }
      }

      if (!verified) {
        if (!turnstileToken) {
          return jsonResponse({ error: "请完成人机验证" }, { status: 400 });
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
              response: turnstileToken,
              remoteip: clientIp,
            }),
          }
        );

        const turnstileResult = await turnstileResponse.json();
        if (!turnstileResult.success) {
          console.error("Turnstile verification failed:", turnstileResult);
          return jsonResponse(
            { error: "人机验证失败，请重新验证后再试" },
            { status: 403 }
          );
        }

        verificationExpiresAt =
          Math.floor(Date.now() / 1000) + verificationWindowSeconds;
        verificationProof = `${verificationExpiresAt}.${await buildVerificationProof(
          verificationExpiresAt
        )}`;
      }

      if (!verificationProof || !verificationExpiresAt) {
        return jsonResponse(
          { error: "Verification state setup failed" },
          { status: 500 }
        );
      }
    }

    pathname = normalizePathname(pathname, { minLength: 5, maxLength: 10 });
    validateTargetUrl(url, env);
    await verifyUrlSafety(url);

    let expiredAtISO = "";
    if (permanent) {
      const configuredPassword = env.PERMANENT_LINK_PASSWORD;

      if (!configuredPassword) {
        return verifiedResponse(
          { error: "Server configuration error: permanent password not set" },
          { status: 500 }
        );
      }

      if (!(await secretMatches(permanentPassword, configuredPassword))) {
        return verifiedResponse(
          { error: "长期短链密码验证失败" },
          { status: 403 }
        );
      }
    } else {
      if (!Number.isInteger(expireDays) || expireDays < 1 || expireDays > 7) {
        return verifiedResponse(
          { error: "Expiration days must be an integer between 1 and 7" },
          { status: 400 }
        );
      }

      const expiredDate = new Date(Date.now() + expireDays * 24 * 3600 * 1000);
      const now = new Date();
      if (isNaN(expiredDate.getTime())) {
        return verifiedResponse({ error: "Invalid timestamp" }, { status: 400 });
      }

      const diffTime = expiredDate.getTime() - now.getTime();
      const diffDays = diffTime / (1000 * 3600 * 24);
      if (diffDays > 7) {
        return verifiedResponse(
          { error: "Expiration date cannot exceed 7 days from now" },
          { status: 400 }
        );
      }

      if (diffTime <= 0) {
        return verifiedResponse(
          { error: "Expiration date must be in the future" },
          { status: 400 }
        );
      }

      expiredAtISO = expiredDate.toISOString();
    }

    let intermediateFile;
    let directFile;
    try {
      [intermediateFile, directFile] = await Promise.all([
        readRulesFile(env, "intermediate"),
        readRulesFile(env, "direct"),
      ]);
    } catch (err) {
      if (err instanceof HttpError) {
        return verifiedResponse({ error: err.message }, { status: err.status });
      }
      throw err;
    }

    let finalPathname = pathname;
    let pathKey = "";

    if (!finalPathname) {
      let attempts = 0;
      do {
        finalPathname = generateRandomPathname();
        pathKey = "/" + finalPathname;
        attempts += 1;
      } while (
        (intermediateFile.rules[pathKey] || directFile.rules[pathKey]) &&
        attempts < 20
      );

      if (
        !pathKey ||
        intermediateFile.rules[pathKey] ||
        directFile.rules[pathKey]
      ) {
        return verifiedResponse(
          { error: "Failed to generate an available pathname" },
          { status: 500 }
        );
      }
    } else {
      pathKey = "/" + finalPathname;
      if (intermediateFile.rules[pathKey] || directFile.rules[pathKey]) {
        return verifiedResponse(
          { error: "Pathname already exists" },
          { status: 409 }
        );
      }
    }

    intermediateFile.rules[pathKey] = {
      url,
      expired_at: expiredAtISO,
    };

    const putRespData = await writeRulesFile(
      env,
      intermediateFile,
      intermediateFile.rules,
      `Add short link: ${finalPathname}`
    );

    return verifiedResponse({
      success: true,
      message: "Short link created",
      short_url: buildShortUrl(env, finalPathname),
      commit_url: buildCommitUrl(env, putRespData),
    });
  } catch (err) {
    if (err instanceof HttpError) {
      return verifiedResponse({ error: err.message }, { status: err.status });
    }
    throw err;
  }
}

async function handleAdminRequest(request, env, requestUrl) {
  const csrfResponse = validateCsrf(request, env);
  if (csrfResponse) return csrfResponse;

  if (requestUrl.pathname === "/api/admin/login") {
    if (request.method !== "POST") return methodNotAllowed();
    return handleAdminLogin(request, env);
  }

  if (
    requestUrl.pathname === "/api/admin/direct" ||
    requestUrl.pathname.startsWith("/api/admin/direct/")
  ) {
    return handleAdminDirect(request, env, requestUrl);
  }

  return jsonResponse({ error: "Not Found" }, { status: 404 });
}

async function handleAdminLogin(request, env) {
  if (!env.ADMIN_PASSWORD) {
    return jsonResponse(
      { error: "Server configuration error: admin password not set" },
      { status: 500 }
    );
  }

  const body = await readJsonBody(request);
  const password = body.password;

  if (!(await secretMatches(password, env.ADMIN_PASSWORD))) {
    return jsonResponse({ error: "管理员密码错误" }, { status: 403 });
  }

  const ttlSeconds = getAdminTokenTtl(env);
  const expiresAt = Math.floor(Date.now() / 1000) + ttlSeconds;
  const token = await createAdminToken(env, expiresAt);

  return jsonResponse({
    success: true,
    token,
    expires_at: expiresAt,
  });
}

function getAdminTokenTtl(env) {
  const configured = Number(env.ADMIN_TOKEN_TTL_SECONDS);
  if (Number.isInteger(configured) && configured > 0 && configured <= 7 * 86400) {
    return configured;
  }
  return 86400;
}

async function createAdminToken(env, expiresAt) {
  const signature = await hmacSha256Hex(
    env.ADMIN_PASSWORD,
    `admin-token|${expiresAt}`
  );
  return `${expiresAt}.${signature}`;
}

async function verifyAdminToken(env, token) {
  if (!env.ADMIN_PASSWORD) {
    throw new HttpError("Server configuration error: admin password not set", 500);
  }

  if (typeof token !== "string" || !token.includes(".")) return false;

  const [expiresAtRaw, signature] = token.split(".");
  const expiresAt = Number(expiresAtRaw);
  if (
    !Number.isInteger(expiresAt) ||
    expiresAt <= Math.floor(Date.now() / 1000) ||
    typeof signature !== "string"
  ) {
    return false;
  }

  const expectedToken = await createAdminToken(env, expiresAt);
  return constantTimeEqual(token, expectedToken);
}

async function requireAdmin(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);

  if (!match || !(await verifyAdminToken(env, match[1]))) {
    return jsonResponse({ error: "Unauthorized" }, { status: 401 });
  }

  return null;
}

async function handleAdminDirect(request, env, requestUrl) {
  const authResponse = await requireAdmin(request, env);
  if (authResponse) return authResponse;

  const basePath = "/api/admin/direct";
  const suffix = requestUrl.pathname.slice(basePath.length);

  if (!suffix) {
    if (request.method === "GET") return listDirectLinks(env);
    if (request.method === "POST") return createDirectLink(request, env);
    return methodNotAllowed();
  }

  const pathname = decodeURIComponent(suffix.replace(/^\/+/, ""));
  if (!pathname || pathname.includes("/")) {
    return jsonResponse({ error: "Invalid pathname" }, { status: 400 });
  }

  if (request.method === "PUT") {
    return updateDirectLink(request, env, pathname);
  }

  if (request.method === "DELETE") {
    return deleteDirectLink(env, pathname);
  }

  return methodNotAllowed();
}

async function listDirectLinks(env) {
  const directFile = await readRulesFile(env, "direct");
  const links = Object.entries(directFile.rules)
    .filter(([pathKey]) => /^\/[a-zA-Z0-9_-]+$/.test(pathKey))
    .map(([pathKey, value]) => {
      const ruleData = getRuleData(value);
      if (!ruleData || typeof ruleData.url !== "string") return null;

      const link = {
        pathname: pathKey.slice(1),
        path: pathKey,
        url: ruleData.url,
      };

      if (ruleData.expired_at) {
        link.expired_at = ruleData.expired_at;
      }

      return link;
    })
    .filter(Boolean)
    .sort((a, b) => a.path.localeCompare(b.path));

  return jsonResponse({ success: true, links });
}

async function createDirectLink(request, env) {
  const body = await readJsonBody(request);
  const pathname = normalizePathname(body.pathname, {
    minLength: 1,
    maxLength: 64,
  });

  if (!pathname) {
    throw new HttpError("Invalid pathname (1-64 chars)", 400);
  }

  validateTargetUrl(body.url, env);
  await verifyUrlSafety(body.url);

  const [directFile, intermediateFile] = await Promise.all([
    readRulesFile(env, "direct"),
    readRulesFile(env, "intermediate"),
  ]);
  const pathKey = "/" + pathname;

  if (directFile.rules[pathKey] || intermediateFile.rules[pathKey]) {
    throw new HttpError("Pathname already exists", 409);
  }

  directFile.rules[pathKey] = {
    url: body.url,
    expired_at: "",
  };

  const putRespData = await writeRulesFile(
    env,
    directFile,
    directFile.rules,
    `Add direct short link: ${pathname}`
  );

  return jsonResponse({
    success: true,
    message: "Direct short link created",
    short_url: buildShortUrl(env, pathname),
    commit_url: buildCommitUrl(env, putRespData),
  });
}

async function updateDirectLink(request, env, rawPathname) {
  const pathname = normalizePathname(rawPathname, {
    minLength: 1,
    maxLength: 64,
  });
  const body = await readJsonBody(request);

  validateTargetUrl(body.url, env);
  await verifyUrlSafety(body.url);

  const directFile = await readRulesFile(env, "direct");
  const pathKey = "/" + pathname;
  const currentRule = getRuleData(directFile.rules[pathKey]);

  if (!currentRule) {
    throw new HttpError("Pathname not found", 404);
  }

  directFile.rules[pathKey] = {
    ...currentRule,
    url: body.url,
    expired_at: currentRule.expired_at || "",
  };

  const putRespData = await writeRulesFile(
    env,
    directFile,
    directFile.rules,
    `Update direct short link: ${pathname}`
  );

  return jsonResponse({
    success: true,
    message: "Direct short link updated",
    short_url: buildShortUrl(env, pathname),
    commit_url: buildCommitUrl(env, putRespData),
  });
}

async function deleteDirectLink(env, rawPathname) {
  const pathname = normalizePathname(rawPathname, {
    minLength: 1,
    maxLength: 64,
  });
  const directFile = await readRulesFile(env, "direct");
  const pathKey = "/" + pathname;

  if (!directFile.rules[pathKey]) {
    throw new HttpError("Pathname not found", 404);
  }

  delete directFile.rules[pathKey];

  const putRespData = await writeRulesFile(
    env,
    directFile,
    directFile.rules,
    `Delete direct short link: ${pathname}`
  );

  return jsonResponse({
    success: true,
    message: "Direct short link deleted",
    commit_url: buildCommitUrl(env, putRespData),
  });
}
