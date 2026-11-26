# AdBlock DNS

自动聚合、清理并编译广告与跟踪拦截规则，提供多客户端订阅，每日自动更新一次。

本项目基于 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 派生，独立维护规则来源、DNS 验证、审计与构建流程。

## 项目状态与使用提示

本项目是新建的持续验证项目，仍处于早期完善阶段。现有上游来源检查、规则解析与清洗、DNS 有效性验证、异常熔断、白名单回归和多客户端产物校验只能降低部分风险，不能保证所有网站、应用和设备均无误拦截或漏拦截。项目没有预先批量添加通用放行域名；误报主要依赖用户提供可复现证据后逐项核实。自动化检查不能替代真实设备与实际使用场景验证。

首次使用或用于重要设备时，建议先观察一段时间，并确认所用客户端支持相应规则格式。遇到网站、应用或系统功能异常，请提交可复现的反馈；项目不承诺零误报或零漏报，也不会仅凭未经验证的单次反馈直接放行域名。

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

本项目不会仅因某一次 DNS 查询失败就删除上游规则中的域名。DNS 验证由 5 个独立上游共同完成：只有当 5 个上游对域名的 A、AAAA 查询均返回 NXDOMAIN 时，才将该域名判定为不存在并从有效规则中排除。只要任一上游返回有效地址，域名就保留；NODATA、超时、SERVFAIL 或上游结果不一致均视为证据不足，不据此删除域名。

- **Full**：包含通过上述 DNS 有效性验证、并经规则处理流程保留的完整规则范围。
- **Lite**：在域名规则基础上，进一步依据国内域名识别数据筛选；识别依据包括国内直连域名规则及中国 IPv4 地址段。它不是简单按数量截短规则，也不是随意删减规则。对于浏览器过滤规则，Lite 按规则关联域名及规则自身的匹配范围筛选，并保留原有匹配语义。

浏览器过滤规则中的元素隐藏、脚本注入、修饰符等语法不等同于 DNS 拦截规则。本项目将浏览器过滤规则与 DNS 域名规则分开处理；请勿把浏览器订阅导入仅支持 DNS 域名的网关，也不要期待 DNS 订阅执行网页元素或脚本过滤。请按客户端支持的格式导入；不同客户端的匹配行为以其自身文档为准。

## 白名单与误报处理

项目维护的独立白名单位于 [rules/white.txt](rules/white.txt)，用于排除有证据支持的正常业务域名误拦截。白名单会参与规则处理，并对 Full 与 Lite 产物执行回归检查；它不是广告规则源，也不应被当作通用放行列表。

白名单采用证据驱动策略：没有足以核实误拦截的有效证据，不添加放行规则。新增或修改条目时，应记录证据链接或脱敏日志摘要、受影响应用/网站与客户端、复现条件、核实日期及放行范围；优先使用精确主机名，避免无必要地放行整个主域名。仅有“网站打不开”或单次解析失败，不足以证明是本项目规则误拦截。详细材料要求见 [反馈与贡献指南](CONTRIBUTING.md)。

## 规则与审计

规则源由 `sources.json` 统一维护。构建流程执行来源检查、去重、DNS 验证、关键域名与白名单回归，并编译客户端格式。验证结果不确定时，不会仅凭一次解析失败删除规则。

- [正式规则 Release](https://github.com/LucentDNS/adblockfilters/releases/tag/rule)
- [审计报告 Release](https://github.com/LucentDNS/adblockfilters/releases/tag/audit)
- [dist 订阅目录](https://github.com/LucentDNS/adblockfilters/tree/dist)
- [上游来源清单](sources.json)

## 集成的上游规则源

以下来源参与正式构建；订阅地址以 `sources.json` 为准。

- AdGuard Base filter — [来源](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt)
- AdGuard Chinese filter — [来源](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt)
- AdGuard Mobile Ads filter — [来源](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt)
- AdGuard DNS filter — [来源](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)
- CJX's Annoyance List — [来源](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt)
- EasyList — [来源](https://easylist-downloads.adblockplus.org/easylist.txt)
- EasyList China — [来源](https://easylist-downloads.adblockplus.org/easylistchina.txt)
- EasyPrivacy — [来源](https://easylist-downloads.adblockplus.org/easyprivacy.txt)
- AWAvenue Ads Rule (Only.Ads) — [来源](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Adguard-Only.Ads.txt)
- HaGeZi DNS-Blocklists (Pro Mini) — [来源](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt)
- StevenBlack hosts — [来源](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)

## 反馈与贡献

欢迎提交可复现的误拦截、漏拦截或构建问题。请先阅读 [反馈与贡献指南](CONTRIBUTING.md)，并使用 GitHub Issues 中对应的反馈模板。规则变更须有可复核证据，不以单纯增加域名数量作为目标。

## 许可与归属

项目代码采用 [GPL-3.0](LICENSE)。本项目基于 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 派生；上游规则保留各自原有归属及许可条件。无法确认再分发条件的来源不纳入正式构建。
