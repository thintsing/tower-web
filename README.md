<div align="center">

<img src="./public/logo.png" width="112" alt="塔台 Tower logo">

# 塔台 Tower Web

**订阅管理、节点测速、多客户端配置导出，一处完成。**

本地优先 · 无需账号 · 所有处理都在本机

[![CI](https://github.com/thintsing/tower-web/actions/workflows/ci.yml/badge.svg)](https://github.com/thintsing/tower-web/actions/workflows/ci.yml)
[![Docker](https://github.com/thintsing/tower-web/actions/workflows/docker.yml/badge.svg)](https://github.com/thintsing/tower-web/actions/workflows/docker.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-1e7b4f?style=flat-square)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20.19-339933?style=flat-square)](https://nodejs.org/)
[![React](https://img.shields.io/badge/react-19-61DAFB?style=flat-square)](https://react.dev/)
[![Vite](https://img.shields.io/badge/vite-7-646CFF?style=flat-square)](https://vite.dev/)

[GitHub 仓库](https://github.com/thintsing/tower-web) ·
[快速开始](#快速开始) · [支持的客户端](#支持的客户端) ·
[已知限制](#已知限制) · [常见问题](#常见问题) · [上游与许可](#上游与许可)

</div>

<p align="center">
  <img src="./docs/screenshot-showcase.png" width="100%" alt="塔台 Tower Web：桌面端与移动端界面">
</p>

<p align="center">
  <a href="./docs/screenshot-desktop.jpg">桌面端原图</a> ·
  <a href="./docs/screenshot-mobile.jpg">移动端原图</a>
</p>

> 截图使用虚构订阅、示例节点和虚构用量，不含真实节点、密码或订阅 token。

本项目是 [塔台 Tower（iOS / macOS）](https://github.com/pengchujin/tower) 的 Web 版本，复用其领域模型、订阅解析语义和区域数据。源码与第三方素材的许可范围不同，详见 [第三方声明](THIRD_PARTY_NOTICES.md)。

> 本项目不提供代理服务或节点，只处理用户自己导入的订阅。请遵守所在地法律法规及订阅服务商的使用条款。

## 功能

- **订阅与节点**：支持订阅 URL、Base64、Clash YAML、Surge / Loon / Quantumult X 配置、sing-box endpoint JSON 和单节点 URI；支持批量添加、刷新、停用、节点排除与搜索。
- **协议**：Shadowsocks / SSR / VMess / VLESS / Trojan / Hysteria / Hysteria 2 / TUIC / WireGuard / AnyTLS / Snell / SOCKS5 / HTTP / SSH / TrustTunnel / MASQUE；按客户端能力自动跳过无法表达的节点。
- **自有节点**：可从链接、配置文本、文件导入，也可逐协议手动新建 / 编辑；不随订阅刷新，可单独启用、停用、改名、删除和标记地区。
- **测速与健康**：本机 TCP / ICMP 测速；订阅页汇总正常、异常、未测节点，可重测失败节点，并在节点详情显示来源、地区、ASN 网络组织和 TLS 信息。
- **规则方案**：内置 ACL4SSR；支持粘贴、文件或 URL 导入 INI、Clash / mihomo、Surge、Egern 和 sing-box 方案。策略组可改名、改类型、编辑候选、调整匹配顺序，并导出 Fluent 图标。
- **规则集**：内置 ACL4SSR 快照与 871 个在线列表；支持本地 / 在线规则集、刷新、暂停、跨客户端引用或无损展开。
- **DNS 与 ECS**：普通 / 国内 / 远程 DNS，跟随方案 / 标准保护 / 严格保护；mihomo 和 sing-box 使用纯节点解析组、DNS 投影与中国子网（ECS）。
- **导出与分享**：一次生成 7 种载体，按客户端设置完整配置 / 仅节点、协议筛选、排序和命名；支持代理集合、Tailscale 内网、二维码和 `clash://` / `surge://` 一键导入。
- **备份**：导出 / 恢复本机 JSON；覆盖恢复前自动保存，本机保留最近 3 份版本。
- **本地优先**：订阅、节点、规则和设置只在本机处理；无账号、云同步、遥测或第三方统计。

## 支持的客户端

| 载体 | 客户端 |
| --- | --- |
| Clash / YAML | Clash Verge、Mihomo Party、FlClash、Clash Mi、Clash、ClashMac、Stash、Karing、Shadowrocket |
| Egern YAML | Egern |
| Surge | Surge、Surge Mac |
| Loon / Quantumult X | Loon、Quantumult X |
| sing-box JSON | sing-box、Hiddify |
| Base64 节点订阅 | V2Box、Anywhere |

- sing-box 没有 SSR 出站，SSR 节点不会写入 JSON。
- 发布订阅时，YAML / Surge / Loon / QuanX / Egern 会按各自规则白名单过滤，避免把其他客户端的规则写进去。
- mihomo 的 ECS 需要较新内核并支持 `#代理组` DNS 后缀；sing-box 的 ECS 需要官方 1.14+，Hiddify 1.13 会跳过 ECS 提示。
- Surge 的仅节点输出是纯 `policy-path` 列表；Quantumult X 的仅节点作为 `server_remote` 资源导入；sing-box MT 完整配置提供「规则判定 / 全局代理 / 直接连接」三种模式。
- 订阅默认请求没有解析到节点时，会自动用 `clash.meta` 兼容 UA 重试；流量或到期信息缺失时会补请求一次配额响应头。
- 闭源客户端按规则白名单和引用完整性自检，仍建议在目标客户端实际导入确认。

## 快速开始

要求 Node.js >= 20.19，推荐使用 `.nvmrc` 指定的 Node 22。

```bash
git clone https://github.com/thintsing/tower-web.git
cd tower-web
npm install

# 开发模式：Web 5173 + API 8787
npm run dev

# 生产模式
npm run build
npm start
```

生产模式打开 <http://127.0.0.1:8787>。本项目需要 Node 运行环境，不能只靠静态托管：订阅发布、规则集托管和 TCP / ICMP 测速都依赖 `server/index.mjs`。

### Docker

镜像发布在 GHCR，支持 linux/amd64 与 linux/arm64：

```bash
docker run -d --name tower-web \
  -p 8787:8787 \
  -v tower-data:/app/data \
  ghcr.io/thintsing/tower-web:latest
```

或用仓库内的编排文件：

```bash
docker compose up -d
```

容器默认 `HOST=0.0.0.0`、`PORT=8787`，打开 <http://127.0.0.1:8787>。已发布订阅保存在数据卷 `/app/data`，重建容器前请保留该卷；也可以用 `TOWER_DATA_DIR` 改路径。ICMP 测速依赖镜像内的 `ping`，不可用时自动回退 TCP。

Docker 内看到的网卡地址不是宿主机地址；如果从本机打开页面又要复制订阅地址给手机，请把 `TOWER_PUBLIC_URL` 设为宿主机的局域网地址：

```bash
docker run -d --name tower-web \
  -p 8787:8787 \
  -v tower-data:/app/data \
  -e TOWER_PUBLIC_URL=http://192.168.1.10:8787 \
  ghcr.io/thintsing/tower-web:latest
```

推送 `v*.*.*` tag 后，GitHub Actions 会自动构建双架构镜像、推送 GHCR 并创建 Release：

```bash
git tag v0.1.0
git push origin v0.1.0
```

> 镜像同样没有鉴权，`-p 8787:8787` 会暴露到局域网，只建议在可信网络使用。

### 局域网 / 手机访问

服务端默认监听 `0.0.0.0`，导出页会显示局域网订阅地址。只允许本机访问时：

```bash
HOST=127.0.0.1 npm start

# Windows PowerShell
$env:HOST='127.0.0.1'; npm start
```

> 局域网模式没有鉴权。`/api/fetch` 可访问任意 http(s) 地址，`/api/probe` 可探测任意主机端口。请只在可信网络使用，不要直接暴露到公网。公网部署需要反向代理、身份验证、限流和日志脱敏，详见 [SECURITY.md](SECURITY.md)。

## 数据与隐私

- 订阅、节点、规则选择和设置保存在浏览器 `localStorage`。
- 已发布订阅保存在 `server/subscriptions.json`（Docker 下为 `/app/data/subscriptions.json`，可用 `TOWER_DATA_DIR` 改路径），已加入 `.gitignore`；**不要提交包含真实机场节点、密码或 token 的文件**。
- 测速由本机 TCP / ICMP 完成；IP 国家 / ASN 查询使用随包离线数据库；二维码的生成、识别和相机画面都不离开本机。
- Tailscale Auth Key 单独保存在本机 localStorage，不进入主快照；下载或发布配置时会写入支持的客户端。

## 常用命令

| 命令 | 说明 |
| --- | --- |
| `npm run dev` | 同时启动 Vite 与本地 API |
| `npm run build` | TypeScript 检查 + 生产构建 |
| `npm start` | 生产模式运行 `server/index.mjs` |
| `npm run selfcheck:clients` | 校验各客户端配置结构 |
| `npm run selfcheck:dns` | 校验 DNS 投影、纯节点组与 ECS |
| `npm run selfcheck:importers` | 校验规则方案导入 |
| `npm run selfcheck:protocols` | 校验协议解析与降级 |

<details>
<summary>全部 16 项自检</summary>

```text
selfcheck:asn         离线 IP / ASN 查询
selfcheck:backup      备份与版本历史
selfcheck:batch       批量订阅导入
selfcheck:catalog     在线规则目录
selfcheck:clients     客户端配置结构
selfcheck:dns         DNS 投影 / 纯节点组 / ECS
selfcheck:importers   Clash / Surge / Egern / sing-box / INI 导入
selfcheck:icons       策略组图标与能力矩阵
selfcheck:manual      自有节点导入与去重
selfcheck:manual-form 手动节点表单
selfcheck:matching    策略组拖动后的规则顺序
selfcheck:protocols   协议解析与客户端降级
selfcheck:qr          二维码生成与解码
selfcheck:remote      代理集合与远程规则集
selfcheck:rulesets    规则集方言转换
selfcheck:yaml        Clash YAML 结构
```

自检只使用虚构示例数据。GitHub Actions 会在 Node 22 上构建并运行全部自检。

</details>

## 已知限制

- 服务端面向本机或可信局域网，没有鉴权、限流或公网防护。
- 不能部署到 GitHub Pages，需要 Node 运行环境；公网部署必须额外加安全层。
- SSR、部分协议和部分规则类型只在支持它的客户端保留，导出页会列出跳过项。
- 规则兼容性、协议能力、Tailscale 和 DNS / ECS 的具体限制随客户端不同，导出前请查看页面提示。
- 数据备份是覆盖恢复，不提供合并；备份不含 Tailscale Auth Key、测速结果和已发布 token。
- 闭源客户端无法自动化导入测试，当前以配置结构、规则白名单和引用完整性自检覆盖。

## 常见问题

**Clash Verge 提示 `unsupported rule type: URL-REGEX`？**  
重新点「一键导入」或「发布订阅」，当前版本会按 mihomo 能力重新生成后再导入。

**sing-box / Egern 里节点数是 0？**  
这些载体不支持 SSR；如果订阅只有 SSR 节点，会全部跳过。

**手机扫不了码或打不开相机？**  
浏览器只在 HTTPS 或 localhost 下允许相机。局域网 HTTP 打开时，请保存二维码图片后用「选择二维码图片」上传。

**订阅链接 404 或连接失败？**  
`server/index.mjs` 没启动、端口变化或 token 失效。保持服务运行，回导出页重新发布并复制新地址。

## 项目结构

```text
src/      React 前端（订阅、节点、规则、导出、地图）
server/   Node 本地服务（订阅抓取、测速、离线 IP / ASN、订阅持久化）
scripts/  自检脚本
public/   客户端图标、ACL4SSR 规则、地图数据
Dockerfile / docker-compose.yml  容器镜像与本地编排
```

## 上游与许可

| 内容 | 来源 | 许可证 |
| --- | --- | --- |
| 领域模型、解析语义、区域数据、项目 Logo | [pengchujin/tower](https://github.com/pengchujin/tower) | MIT |
| ACL4SSR 规则数据 | [ACL4SSR](https://github.com/ACL4SSR/ACL4SSR/tree/802e3abf065f8609e7d9073ba506158dbe2ba6e7) | CC BY-SA 4.0 |
| 离线 IP 国家 / ASN 库 | [sapics/ip-location-db](https://github.com/sapics/ip-location-db) | PDDL-1.0 |
| 世界地图 | [world-atlas](https://github.com/topojson/world-atlas) / [Natural Earth](https://www.naturalearthdata.com/) | ISC / public domain |
| 客户端图标 | 各客户端官方素材 | 商标 / 各自版权 |
| npm 依赖 | 各上游仓库 | MIT / ISC 等 |

- **源码**：MIT，见 [LICENSE](LICENSE)。
- **规则数据**：CC BY-SA 4.0，见 [规则 NOTICE](public/rulesets/NOTICE.md)。
- **客户端图标**：不适用 MIT，见 [图标 NOTICE](public/client-icons/NOTICE.md)。
- **IP / ASN 数据**：PDDL-1.0，见 [IP NOTICE](server/ip-country/NOTICE.txt) 和 [ASN NOTICE](server/ip-asn/NOTICE.txt)。
- 完整依赖与素材说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

---

<div align="center">

[GitHub 仓库](https://github.com/thintsing/tower-web) ·
[版本发布](https://github.com/thintsing/tower-web/releases) ·
[反馈问题](https://github.com/thintsing/tower-web/issues) ·
[塔台 Tower（iOS / macOS）](https://github.com/pengchujin/tower) ·
[安全策略](SECURITY.md) ·
[MIT License](LICENSE)

</div>
