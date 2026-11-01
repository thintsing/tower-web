# Security policy

Tower Web 是一个本地优先的工具，默认设计用于本机或可信局域网，不是面向公网的多租户服务。

## 部署警告

- 不要直接把 `server/index.mjs` 暴露到公网。
- 服务端没有身份验证、限流或权限隔离：
  - `/api/fetch` 可代理任意 http(s) 地址；
  - `/api/probe` 可探测任意主机端口；
  - `/api/subscribe` 可写入订阅 token；
  - `/api/sub/:token` 可读取已发布配置。
- 公开部署前至少需要：反向代理 + 身份验证、网络访问控制、限流、审计日志，以及为订阅管理增加用户隔离。
- 不需要局域网访问时，用 `HOST=127.0.0.1` 启动。

## 敏感数据

- `server/subscriptions.json` 会保存真实订阅内容（可能包含节点地址、密码、UUID、token，以及 Tailscale Auth Key）。
- 该文件已在 `.gitignore` 中排除，**不要提交到 GitHub，也不要在 Issue / 日志 / 截图中粘贴真实订阅内容**。
- Tailscale 连接的 Auth Key 另存在浏览器 localStorage 的 `tower-web-tailnet-auth-keys` 记录里，不进入主快照；它不是操作系统钥匙串，同浏览器的其他脚本仍可读取，建议在可信设备上使用。
- 配置预览会把已启用的 Auth Key 打码，但下载文件、复制内容和已发布订阅都包含真实 Key。
- 修改或删除 Tailscale 内网后，已发布的订阅不会自动变化；请回导出页同步链接，否则旧链接在同步前仍会返回旧 Auth Key。
- 如果曾误提交，请视为凭据泄露：删除文件、清理 Git 历史，并在订阅服务商 / Tailscale 后台撤销相关凭据。

## 报告问题

请使用 GitHub 的 Security Advisory / 私密漏洞报告功能，不要在公开 Issue 中附带可用的订阅链接或节点凭据。
