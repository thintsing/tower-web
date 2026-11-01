# Third-party notices

Tower Web 的源码以 **MIT** 许可发布，见仓库根目录 `LICENSE`。
但下列第三方素材、规则数据、图标和依赖**不适用 MIT**，各自保留原有许可或权利。

## 上游项目

| 上游 | 链接 | 许可证 | 本项目使用方式 |
| --- | --- | --- | --- |
| 塔台 Tower（iOS / macOS） | <https://github.com/pengchujin/tower> | MIT | Web 版本的领域模型、解析语义、区域数据、交互参考和项目 Logo |
| ACL4SSR | <https://github.com/ACL4SSR/ACL4SSR> | CC BY-SA 4.0 | `public/rulesets/` 规则数据与在线目录路径 |
| blackmatrix7/ios_rule_script | <https://github.com/blackmatrix7/ios_rule_script> | GPL-2.0 | 在线规则目录路径；规则内容不随本项目分发 |
| sapics/ip-location-db | <https://github.com/sapics/ip-location-db> | PDDL-1.0 | `server/ip-country/` 离线 IP 国家库 |
| world-atlas | <https://github.com/topojson/world-atlas> | ISC | `public/world-atlas.json` |
| Natural Earth | <https://www.naturalearthdata.com/> | Public domain | 地图与国家/地区坐标来源 |
| IBM Plex | <https://github.com/IBM/plex> | SIL OFL 1.1 | 通过 Google Fonts 运行时加载 |

Tower Web 不是 Tower iOS 的官方发行版，也不代表上游对本项目的背书。

## 1. Tower iOS 代码与区域数据

- 上游：<https://github.com/pengchujin/tower>
- 上游许可证与第三方声明：仓库根目录的 `LICENSE` / `THIRD-PARTY-NOTICES.md`
- 许可证：MIT（Copyright (c) 2026 pengchujin）
- 复用范围：`src/models/`、`src/parser/` 等领域模型和解析语义，
  `src/models/tailnet.ts`、`src/generator/tailnet.ts` 的 Tailscale 内网导出语义，
  `src/data/regions.json` 中的国家/地区数据，以及 `public/logo.png` /
  `public/favicon.png` 项目 Logo（取自上游 `docs/images/icon.png`，未修改图案）。
- `src/data/regions.json` 来自 Tower iOS 的 `CountryTable.swift` 生成数据；
  Tower iOS 的国名、别名和坐标基于 Natural Earth `ne_110m_admin_0_countries`，
  Natural Earth 为公共领域。
- Tower iOS 中随 App 打包的第三方规则、IP 数据库、图标等不适用 MIT；
  本仓库只使用了其中与本项目相关的 ACL4SSR 规则、离线 IP 国家库和客户端图标，
  并分别在本文件、`public/rulesets/NOTICE.md`、`server/ip-country/NOTICE.txt`、
  `public/client-icons/NOTICE.md` 中标注。

## 2. ACL4SSR 规则集

- 上游：<https://github.com/ACL4SSR/ACL4SSR>
- 固定版本：`802e3abf065f8609e7d9073ba506158dbe2ba6e7`
- 位置：`public/rulesets/ACL4SSR_*.ini`、`public/rulesets/ACL4SSR_*.list`
- 许可证：**CC BY-SA 4.0**
  <https://creativecommons.org/licenses/by-sa/4.0/legalcode>
- 署名：ACL4SSR 项目及其贡献者。
- 修改：规则内容未修改；文件名统一增加 `ACL4SSR_` 前缀；部分 `.ini` 中的上游
  `master` 链接改写为上述固定提交，以保证可复现。
- 再分发：这些规则文件及其改编必须继续以 CC BY-SA 4.0 或兼容许可分发，并保留
  署名和许可证链接。由本工具生成、包含这些规则的配置文本，如对外再分发，其规则
  部分同样应按 CC BY-SA 4.0 处理。完整说明见 `public/rulesets/NOTICE.md`。

## 2a. 在线规则目录索引

- 位置：`src/data/ruleCatalogIndex.ts`（以及生成前的
  `src/data/ACL4SSR.list-index.txt`、`src/data/blackmatrix7.list-index.txt`）。
- 来源：移植自 Tower iOS `Tower/Resources/RuleCatalog/` 的列表路径索引。
- ACL4SSR 路径：<https://github.com/ACL4SSR/ACL4SSR>，**CC BY-SA 4.0**；
  目录版本固定为 `06ff293e02565adceef9aa92321efa2603f68f32`。
- blackmatrix7 路径：<https://github.com/blackmatrix7/ios_rule_script>，
  **GPL-2.0**。本项目只保存上游列表的路径、名称和来源地址，**不打包规则内容**；
  用户添加时由本机 `/api/fetch` 从上游读取，规则内容不会随本仓库再分发。
- 如再分发这些索引路径或修改后的目录，请保留上述署名、许可证和来源链接。

## 3. 地图数据

- `public/world-atlas.json`：world-atlas 2.x 的 `countries-110m` TopoJSON。
- 上游：<https://github.com/topojson/world-atlas>
- 许可证：ISC（以 world-atlas 包内声明为准）。
- 原始地理数据：Natural Earth，<https://www.naturalearthdata.com/>，公共领域。
- 本项目只做了打包和读取，没有修改地理数据内容。

## 4. 离线 IP 国家 / ASN 库

- 位置：`server/ip-country/IPCountryIPv4.bin`、`IPCountryIPv6.bin`、
  `IPCountryVersion.txt`、`NOTICE.txt`；网络组织表位于
  `server/ip-asn/IPASNIPv4.bin`、`IPASNIPv6.bin`、`IPASNNames.bin`、`NOTICE.txt`。
- 派生数据：`src/rules/chinaCIDRs.ts` 从同一份 `server-country` 数据提取中国大陆
  IPv4 / IPv6 网段，供 sing-box 的 ECS 响应匹配使用；未修改原始地理数据。
- 上游：<https://github.com/sapics/ip-location-db>
- 数据来源：上游的 `server-country` 与 `origin-asn` 系列，按国家/地区归类的
  IP 段数据，以及按自治系统归类的网络组织数据。
- 许可证：**PDDL-1.0**（Public Domain Dedication and License 1.0）
  <https://opendatacommons.org/licenses/pddl/1-0/>
- 署名：sapics/ip-location-db 项目及上游数据贡献者。
- 修改：本项目未修改二进制数据，仅按上游给定的记录格式读取；`IPCountryVersion.txt`
  记录随包版本，`NOTICE.txt` 保留上游声明原文。
- 使用方式：`/api/ip-country` 在本机解析域名并查询随包数据，不向第三方发起 IP
  地理位置查询请求。
- 再分发：数据本身以 PDDL-1.0 提供，可自由使用、修改和再分发；如再分发本目录
  数据，请保留本说明与上游 `NOTICE.txt`。

## 5. 客户端图标

`public/client-icons/` 中图标用于在导出页标识对应客户端，**不适用 MIT**，相关名称、
图标和商标归各自权利人所有。本项目与这些客户端开发者无隶属、赞助或背书关系，
也不分发客户端软件本身。

完整权利人、来源和商标说明见 [`public/client-icons/NOTICE.md`](./public/client-icons/NOTICE.md)。
权利人如有异议，可通过仓库 Issue 联系移除或替换为通用占位图标。

## 5a. 策略组图标

导出配置里的策略组图标不随本仓库打包，只写入固定版本的 CDN / GitHub 原始文件地址：

- **Emoji 图片**：Microsoft Fluent Emoji 3D，MIT，固定提交
  [`1ffb34c`](https://github.com/microsoft/fluentui-emoji/tree/1ffb34c752ecf5d402f04cfb4b392c77f57c54bc)，经 jsDelivr 引用。
- **圆形国旗 / 圆底图标**：flag-icons 1x1（MIT，固定提交
  [`ac7e0eb`](https://github.com/lipis/flag-icons/tree/ac7e0eb3259eb62aa6100c435607e2fe03896a97)）以及 Tower iOS
  在固定提交 [`425b0a7`](https://github.com/pengchujin/tower/tree/425b0a7acce67b19f442d01a0722c2ae4cf8a477)
  （国旗）和 [`b1cfedc`](https://github.com/pengchujin/tower/tree/b1cfedcb29b4a6498a7331ebf5021fc0d84d57ad)
  （QuanX 圆底）发布的 PNG 产物。
- 这些图片不适用本项目 MIT，权利人及许可以上表上游为准。离线或 CDN 不可达时，
  客户端可能只显示组名。

## 6. 字体

- IBM Plex Sans / IBM Plex Mono 通过 Google Fonts 的 CSS 在运行时加载，未随仓库
  打包字体文件。
- 上游：<https://github.com/IBM/plex>
- 许可证：SIL Open Font License 1.1。

## 7. npm 依赖

直接依赖的主要许可证与上游仓库：

| 依赖 | 许可证 | 上游 |
| --- | --- | --- |
| react / react-dom | MIT | <https://github.com/facebook/react> |
| react-simple-maps | MIT | <https://github.com/zcreativelabs/react-simple-maps> |
| d3-geo | ISC | <https://github.com/d3/d3-geo> |
| topojson-client | ISC | <https://github.com/topojson/topojson-client> |
| world-atlas | ISC | <https://github.com/topojson/world-atlas> |
| yaml | ISC | <https://github.com/eemeli/yaml> |
| zustand | MIT | <https://github.com/pmndrs/zustand> |
| uqr | MIT | <https://github.com/unjs/uqr> |
| jsqr | Apache-2.0 | <https://github.com/cozmo/jsQR> |
| vite | MIT | <https://github.com/vitejs/vite> |
| @vitejs/plugin-react | MIT | <https://github.com/vitejs/vite-plugin-react> |
| typescript | Apache-2.0 | <https://github.com/microsoft/TypeScript> |
| tsx | MIT | <https://github.com/privatenumber/tsx> |
| concurrently | MIT | <https://github.com/open-cli-tools/concurrently> |

完整依赖树与版本以 `package.json`、`package-lock.json` 和 `node_modules/*/package.json`
中的许可证字段为准。

## 8. 客户端配置格式

Surge、Clash / mihomo、Stash、Loon、Quantumult X、sing-box、Shadowrocket、Egern 等
配置格式的规范归各自客户端开发者所有。本项目只按公开文档生成配置文本，不包含、
不修改、不分发任何客户端软件。

Tailscale / Tailnet 名称与相关商标归 Tailscale Inc. 所有。本项目只生成客户端配置，
不包含、不分发 Tailscale 客户端或服务，也不代表 Tailscale 对本项目的背书。

---

本文件仅用于记录来源与许可提示，不构成法律意见。发布或商业再分发前，请自行核对
上游最新许可证与商标使用要求。
