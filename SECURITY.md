# Security policy

Tower Web 是一个本地优先的工具，默认设计用于本机或可信局域网，不是面向公网的多租户服务。

## 部署警告

- 不要直接把 `server/index.mjs` 暴露到公网。
- 服务端默认没有身份验证、限流或权限隔离：
  - `/api/fetch` 可代理任意 http(s) 地址；
  - `/api/probe` 可探测任意主机端口；
  - `/api/subscribe` 可写入订阅 token；
  - `/api/sub/:token` 可读取已发布配置。
- 可以在「订阅设置 → 局域网与访问密钥」关闭局域网共享，或生成管理 API 访问密钥。启用后，非本机请求调用管理 API 必须带 `key` / `X-Tower-Key` / Bearer；页面用 `?key=` 打开会种下 HttpOnly cookie。默认本地模式下本机 `127.0.0.1` / `::1` 不需要密钥；服务器模式没有这个豁免，见下节。
- Docker 下宿主机页面通常以私有地址 + `Host: localhost` 出现，服务端据此识别宿主机。启用密钥后，这类请求同样必须带正确密钥，伪造 Host 不能读取 `settings.json` 或管理密钥；没有密钥时也不能仅凭伪造 Host 创建首个密钥，首次密钥请用 `TOWER_API_TOKEN` 或在容器内对回环地址调用 `/api/settings/token`。关闭共享时该识别只保留 `/api/settings`、`/api/auth-status`、`/api/health` 以便宿主机恢复设置，订阅、规则集和代理端点仍拒绝；但它不能替代网络隔离。
- 免管理密钥但仍受局域网共享开关约束的端点：`/api/health`、`/api/auth-status`、`/api/ruleset`，以及 GET `/api/sub/:token`、GET `/api/s/:token`。订阅 / 分享 token 和托管规则集地址本身是独立凭证，拿到即可读取对应内容。
- `/api/ruleset?url=` 只接受 http/https，并拒绝链路本地（`169.254.0.0/16`、`fd00:ec2::254`、`100.100.100.200`）与云元数据主机名；私有网段仍然允许，供自建 NAS 规则集使用。DNS rebinding 不在防护范围内。
- 密钥只保护管理 API，不是公网级身份认证；公开部署前至少需要：反向代理 + 身份验证、网络访问控制、限流、审计日志，以及为订阅管理增加用户隔离。
- 不需要局域网访问时，用 `HOST=127.0.0.1` 启动，或在设置页关闭局域网共享。

### 服务器版（`TOWER_MODE=server`）

- `/api/workspace`、`/api/workspace/version` 始终要求访问密钥，`127.0.0.1` / `::1` 也不例外。否则局域网客户端只要伪造 `Host: localhost` 就能读写整份工作区。
- `/api/auth-status` 会返回 `mode: "server"`；密钥来源与其它管理 API 相同（`?key=`、`X-Tower-Key`、`Authorization: Bearer`、`tower_key` cookie），没有另造一套。
- 密钥长度放宽为 1–128 个非空白字符（首尾 trim，内部空白 / 换行 / 控制字符拒绝）。短密钥（1–15 字符）可被暴力穷举；同一 IP 连续 10 次认证失败只冷却 60 秒，不能替代强密钥。建议至少 16 位随机字符，并在可信网络内使用。
- 工作区接口只做认证失败节流，不做公网级限流、用户隔离或审计；不要把服务器模式直接暴露到公网。
- 单用户模型：没有角色、多人合并和资源级权限。409 是版本冲突（另一台设备刚写入），不是权限错误；客户端会载入最新版本，旧编辑不会保留。
- 首次迁移时，如果服务端还没有 `workspace.json`，第一个带密钥打开的客户端会上传它本机的工作区；服务端已有数据后，只能按当前版本号覆盖，不能静默清空。

## 敏感数据

- `server/subscriptions.json` 只保存已发布/生成好的客户端配置文本（按 token 索引），不是订阅源、解析后的节点或规则工作区；内容可能包含节点地址、密码、UUID、token，以及 Tailscale Auth Key。
- 默认本地模式下，订阅源、解析后的节点、规则方案、规则集和当前选择保存在浏览器 localStorage（`tower-web-state`）；不同电脑或浏览器 profile 不共享，换机需要重新添加订阅或导出/导入备份。
- 服务器模式下，同一份工作区（含订阅源、节点凭据、规则、当前选择和 Tailscale Auth Key）保存在 `TOWER_DATA_DIR/workspace.json`。它与 `subscriptions.json` 同级敏感：不要提交、不要在 Issue / 日志 / 截图中粘贴，并限制数据目录的文件权限。服务端会在同目录保留 `workspace.json.bak` 和损坏现场 `workspace.json.broken-<时间戳>`，同样按敏感文件处理。
- `server/settings.json` 保存局域网共享开关和管理 API 访问密钥（Docker 下位于 `/app/data/settings.json`），同样不要提交或分享。
- 这些运行数据文件已在 `.gitignore` 中排除，**不要提交到 GitHub，也不要在 Issue / 日志 / 截图中粘贴真实订阅内容或访问密钥**。
- 本地模式下，Tailscale 连接的 Auth Key 另存在浏览器 localStorage 的 `tower-web-tailnet-auth-keys` 记录里，不进入主快照；它不是操作系统钥匙串，同浏览器的其他脚本仍可读取，建议在可信设备上使用。服务器模式下 Auth Key 随工作区保存在服务端，并同步到每台打开的设备。
- 配置预览会把已启用的 Auth Key 打码，但下载文件、复制内容和已发布订阅都包含真实 Key。
- 修改或删除 Tailscale 内网后，已发布的订阅不会自动变化；请回导出页同步链接，否则旧链接在同步前仍会返回旧 Auth Key。
- 如果曾误提交，请视为凭据泄露：删除文件、清理 Git 历史，并在订阅服务商 / Tailscale 后台撤销相关凭据。

## 报告问题

请使用 GitHub 的 Security Advisory / 私密漏洞报告功能，不要在公开 Issue 中附带可用的订阅链接或节点凭据。
