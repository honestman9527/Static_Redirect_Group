# 静态重定向服务 (Static Redirect Service)

这是一个基于 Cloudflare Worker 的全功能短链服务。它无需服务器，利用 Cloudflare Worker 同时托管静态页面（前端）和 API（后端），并使用 GitHub 仓库作为“数据库”存储重定向规则。

## 功能特性

- **完全免费**: 依托 Cloudflare Workers 免费额度。
- **零成本托管**: 无需购买服务器，无需 GitHub Pages，一个 Worker 搞定所有。
- **两种重定向模式**:
  - **直接跳转**: 访问短链直接跳转到目标地址。
  - **中间页跳转**: 显示一个安全提示卡片，用户需点击“继续访问”才跳转（适合外部或敏感链接，防止误触）。
- **自助创建**: 提供 `/_url` 界面，允许访客自助创建短链。
- **安全防护**:
  - 防 XSS、防 HTML 注入。
  - 防循环重定向（禁止套娃）。
  - CSRF 保护。
  - 目标 URL 有效性检查（死链无法创建）。
  - **Cloudflare Turnstile 人机验证**（可选）。
- **自动过期**: 支持设置短链有效期（最长 7 天），过期自动清理。

## ❤️ 赞助

如果这个项目对你有帮助，欢迎 [赞助我](https://2x.nz/sponsors) 或给一个 Star ⭐️！

## 搭建你的短链

> 本来想让 AI 写的，但是它写的太煞笔了，这里就给一个简单的部署教程，之后会写一篇文章详细教你部署，请关注我的博客！ https://2x.nz

1. Fork 本仓库

2. 创建 Cloudflare Worker，连接本仓库

3. 更改静态 HTML 内硬编码的内容

4. 清理短链。并创建你需要的短链（此时，静态重定向功能已经完全可用）

5. 创建 GithubToken

6. 绑定各个机密环境变量

7. （可选）配置 Cloudflare Turnstile 人机验证：

   - 在 [Cloudflare Dashboard](https://dash.cloudflare.com/?to=/:account/turnstile) 创建 Turnstile 站点
   - 获取 Site Key 和 Secret Key
   - 将 `_url.html` 中的 `YOUR_SITE_KEY` 替换为你的 Site Key
   - 在 Worker 环境变量中添加 `TURNSTILE_SECRET_KEY`

8. 访问 /\_url 即可创建短链（此时，动态创建短链功能已经完全可用）
