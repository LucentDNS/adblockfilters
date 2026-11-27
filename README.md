# AdBlock DNS

自动聚合、清理并编译广告与跟踪拦截规则，提供多客户端订阅，每日自动更新一次。

本项目基于 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 派生，独立维护规则来源、DNS 验证、审计与构建流程。

## 项目状态与使用提示

本项目是新建的持续验证项目，仍处于早期完善阶段。现有上游来源检查、规则解析与清洗、DNS 有效性验证、异常熔断、白名单回归和多客户端产物校验只能降低部分风险，不能保证所有网站、应用和设备均无误拦截或漏拦截。**上游规则源的接入不代表逐条人工预审，也不代表已对每条规则完成独立质量背书；项目没有覆盖所有域名的前置自动误报扫描。** 自动化检查侧重来源可用性、规则处理、DNS 有效性与产物回归，不能证明每条规则都不会影响正常业务，也不能替代真实设备与实际使用场景验证。误报主要依赖用户提供可复现证据后逐项核实。

项目没有预先批量添加通用放行域名。首次使用或用于重要设备时，建议先观察一段时间，并确认所用客户端支持相应规则格式。遇到网站、应用或系统功能异常，请提交可复现的反馈；项目不承诺零误报或零漏报，也不会仅凭未经验证的单次反馈直接放行域名。

## 订阅

提供 **Full** 与 **Lite** 两种版本，共 35 个订阅文件。建议使用下表中的 Raw 链接。

| 客户端 / 格式 | Full | Lite |
|---|---|---|
| AdGuard DNS / AdGuard Home | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnslite.txt) |
| AdGuard 浏览器扩展（补充规则） | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilters.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilterslite.txt) |
| InviZible Pro DNSCrypt | [拦截](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomain.txt) · [放行](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainallow.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainlite.txt) |
| DNSMasq | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasq.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasqlite.txt) |
| SmartDNS | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdns.conf) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdnslite.conf) |
| Clash 规则集 | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclash.list) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclashlite.list) |
| Shadowrocket 模块 | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocket.sgmodule) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocketlite.sgmodule) |
| Quantumult X | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqx.conf) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqxlite.conf) |
| Mihomo YAML | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.yaml) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.yaml) |
| Mihomo MRS | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.mrs) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.mrs) |
| Hosts | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhosts.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhostslite.txt) |
| sing-box JSON | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.json) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.json) |
| sing-box SRS | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.srs) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.srs) |
| Loon | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloon.list) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloonlite.list) |
| Surge | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurge.list) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurgelite.list) |
| MosDNS | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdns.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdnslite.txt) |
| V2Ray / Xray | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2ray.dat) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2raylite.dat) |

### Full 与 Lite 的区别

本项目不会仅因某一次 DNS 查询失败就删除上游规则中的域名。DNS 验证由 5 个独立上游共同完成：只有当 5 个上游对域名的 A、AAAA 查询均返回 NXDOMAIN 时，才将该域名判定为不存在并从有效规则中排除。只要任一上游返回有效地址，域名就保留；NODATA、超时、SERVFAIL 或上游结果不一致均视为证据不足，不据此删除域名。这一步只做 DNS 存活性清理：它只识别有充分 DNS 证据表明已经不存在的域名，**不检测、不判断、也不自动修复误拦截**。个别域名确认死亡时只剔除该域名，其余规则继续处理；若验证结果显示 DNS 基础设施整体退化（例如大量查询持续出现不确定结果），则阻断本轮 DNS 状态发布及后续正式构建，而不是把服务故障当成域名死亡。验证使用 5 个独立上游，限制并发并错开查询启动；每轮会保存 DNS 查询摘要、输入来源信息和分类结果为 GitHub Actions artifact，保留 30 天，便于追查清理依据。

- **Full**：包含通过上述 DNS 有效性验证、并经规则处理流程保留的完整规则范围。
- **Lite**：在域名规则基础上，进一步依据国内域名识别数据筛选；识别依据包括国内直连域名规则及中国 IPv4 地址段。它不是简单按数量截短规则，也不是随意删减规则。对于浏览器过滤规则，Lite 按规则关联域名及规则自身的匹配范围筛选，并保留原有匹配语义。

浏览器过滤规则中的元素隐藏、脚本注入、修饰符等语法不等同于 DNS 拦截规则。本项目将浏览器过滤规则与 DNS 域名规则分开处理；请勿把浏览器订阅导入仅支持 DNS 域名的网关，也不要期待 DNS 订阅执行网页元素或脚本过滤。DNS Full/Lite 使用 AdGuard Home 的 Adblock-style 域名语法（例如 `||example.com^`、`@@||example.com^`），每次构建都会使用 AdGuard 官方 [Hostlist Compiler](https://github.com/AdguardTeam/HostlistCompiler) v2.1.1 对两个 DNS 产物执行 `Validate` 与 `Deduplicate` 独立校验；如果编译器删除、改写规则，或发现重复规则，校验就会失败，阻止本轮正式发布。**这项检查验证的是 DNS 列表语法和编译器兼容性，不代表自动判断了域名是否真是广告/跟踪，也不代表已经排除了误拦截。** 请按客户端支持的格式导入；不同客户端的匹配行为以其自身文档为准。规则编写参考 [AdGuard 官方指南](https://adguard.com/kb/general/ad-filtering/create-own-filters/)。DNS 主机名规则只保留作用范围固定在已知注册域名之下的模式；通配注册域/TLD 的宽泛模式、正则规则，以及需要特殊上下文或规则集级处理的修饰符不进入 DNS 输出。对于 AdGuard Home 支持且可原样保留的 `$dnstype`，项目保留原始规则及其记录类型限制，不将其改写成无条件拦截。通配模式不是可直接查询的完整域名，因此不做 A/AAAA 存活性探测，只接受语法校验；Lite 仅保留其固定注册域名命中国内域名集合的模式。通配模式只输出到 AdGuard DNS Full/Lite 订阅；Hosts、DNSMasq 等其他格式继续只输出其可准确表达的精确域名规则。

## 白名单与误报处理

项目维护的独立白名单位于 [rules/white.txt](rules/white.txt)，用于排除有证据支持的正常业务域名误拦截。白名单会参与规则处理，并对 Full 与 Lite 产物执行回归检查；它不是广告规则源，也不应被当作通用放行列表。

白名单采用证据驱动策略：没有足以核实误拦截的有效证据，不添加放行规则。新增或修改条目时，应记录证据链接或脱敏日志摘要、受影响应用/网站与客户端、复现条件、核实日期及放行范围；优先使用精确主机名，避免无必要地放行整个主域名。仅有“网站打不开”或单次解析失败，不足以证明是本项目规则误拦截。详细材料要求见 [反馈与贡献指南](CONTRIBUTING.md)。

## 规则与审计

规则源由 `sources.json` 统一维护。构建流程执行来源检查、去重、DNS 验证、关键域名与白名单回归，并编译客户端格式。验证结果不确定时，不会仅凭一次解析失败删除规则。

- [正式规则 Release](https://github.com/LucentDNS/adblockfilters/releases/tag/rule)
- [审计报告 Release](https://github.com/LucentDNS/adblockfilters/releases/tag/audit)
- [dist 订阅目录](https://github.com/LucentDNS/adblockfilters/tree/dist)
- [上游来源清单](sources.json)（单个来源可通过设置 `"enabled": false` 临时停用；省略该字段时默认启用，恢复时删除该字段或设为 `true`）

## 集成的上游规则源

以下来源参与正式构建；订阅地址以 `sources.json` 为准。DNS 来源与浏览器补充来源分开处理，不把浏览器规则提取出的域名混入 DNS 规则。

### DNS/Hosts 正式来源（进入 DNS Full/Lite）

- AdGuard DNS filter — [来源](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)
- AWAvenue Ads Rule (Only.Ads) — [来源](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Adguard-Only.Ads.txt)
- anti-AD (AdGuard DNS rules) — [来源](https://anti-ad.net/easylist.txt)
- HaGeZi DNS-Blocklists (Pro Mini) — [来源](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt)
- StevenBlack hosts — [来源](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)

### 浏览器补充来源（只进入浏览器过滤产物，不进入 DNS）

- AdGuard Base filter — [来源](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt)
- AdGuard Chinese filter — [来源](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt)
- AdGuard Mobile Ads filter — [来源](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt)
- CJX's Annoyance List — [来源](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt)
- EasyList — [来源](https://easylist-downloads.adblockplus.org/easylist.txt)
- EasyList China — [来源](https://easylist-downloads.adblockplus.org/easylistchina.txt)
- EasyPrivacy — [来源](https://easylist-downloads.adblockplus.org/easyprivacy.txt)

### 官方列表基准审计（仅候选，不参与正式构建）

项目会对 AdGuard [HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry) 中已收录的 AdRules DNS、OISD Small/Big、1Hosts Lite、HaGeZi Pro/Normal 等列表进行候选源贡献审计。它们目前仅用于比较解析覆盖、与现有来源的重合及潜在增量，不会自动并入正式规则；是否集成还需单独审查误报风险、DNS 验证证据、语法兼容性和许可条件。

## 反馈与贡献

欢迎提交可复现的误拦截、漏拦截或构建问题。请先阅读 [反馈与贡献指南](CONTRIBUTING.md)，并使用 GitHub Issues 中对应的反馈模板。规则变更须有可复核证据，不以单纯增加域名数量作为目标。

## 许可与归属

项目仓库级代码许可证为 [GPL-3.0](LICENSE)，与本项目基于 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 派生的代码基础一致。该许可证声明不应被理解为把所有第三方规则数据统一改许可；上游规则及其原始归属、版权声明和许可条件仍须分别遵守。

当前来源清单中可核对的上游仓库/发布方许可信息如下。这里列出的是上游仓库或发布方公开声明，不代表对每一条规则的版权来源作出独立法律鉴定；如具体文件附有不同声明，应以该文件及其上游说明为准。

| 上游来源 | 公开许可信息 |
|---|---|
| AdGuard Base / Chinese（FiltersRegistry） | [LGPL-3.0](https://github.com/AdguardTeam/FiltersRegistry/blob/master/LICENSE) |
| AdGuard Mobile Ads（AdguardFilters） | [GPL-3.0](https://github.com/AdguardTeam/AdguardFilters/blob/master/LICENSE) |
| AdGuard DNS filter | [GPL-3.0](https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE) |
| CJX's Annoyance List | [LGPL-3.0](https://github.com/cjx82630/cjxlist)（以该仓库当前许可声明为准） |
| EasyList / EasyPrivacy | [GPL-3.0-or-later 或 CC BY-SA 3.0-or-later](https://easylist.to/pages/licence.html) |
| EasyList China | 独立托管的列表；不得仅凭名称推定与 EasyList 主列表许可完全相同，应核对发布方对该文件的具体条款 |
| AWAvenue Ads Rule | [GPL-3.0](https://github.com/TG-Twilight/AWAvenue-Ads-Rule/blob/main/LICENSE) |
| anti-AD | [MIT](https://github.com/privacy-protection-tools/anti-AD/blob/master/LICENSE) |
| HaGeZi DNS-Blocklists | [GPL-3.0](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE) |
| StevenBlack hosts | [MIT](https://github.com/StevenBlack/hosts/blob/master/license.txt) |

AdRules、Anti-AD、OISD 与 1Hosts 等候选列表当前不在本项目的 `sources.json` 中，因此不属于正式构建来源，也不在上表中。来源清单发生变化时，应同步复核其具体许可与再分发条件。无法确认再分发条件的来源不纳入正式构建。
