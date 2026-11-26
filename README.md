# AdBlock DNS

自动聚合、清理并编译广告与跟踪拦截规则，提供多客户端订阅，按计划自动更新。

本项目基于 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 派生，独立维护规则来源、DNS 验证、审计与构建流程。

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

Lite 为精简版本，规则覆盖范围与 Full 不同。请按客户端支持的格式导入；不同客户端的匹配行为以其自身文档为准。

## 规则与审计

规则源由 `sources.json` 统一维护。构建流程执行来源检查、去重、DNS 验证、关键域名与白名单回归，并编译客户端格式。验证结果不确定时，不会仅凭一次解析失败删除规则。

- [正式规则 Release](https://github.com/LucentDNS/adblockfilters/releases/tag/rule)
- [审计报告 Release](https://github.com/LucentDNS/adblockfilters/releases/tag/audit)
- [dist 订阅目录](https://github.com/LucentDNS/adblockfilters/tree/dist)
- [上游来源清单](sources.json)

## 上游来源

感谢以下项目及维护者。各来源的具体订阅地址和类型以 [sources.json](sources.json) 为准。

[AdGuard](https://github.com/AdguardTeam/AdguardFilters) · [AdGuard DNS](https://github.com/AdguardTeam/AdGuardSDNSFilter) · [CJX's Annoyance List](https://github.com/cjx82630/cjxlist) · [EasyList](https://easylist.to/) · [AWAvenue Ads Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) · [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) · [StevenBlack hosts](https://github.com/StevenBlack/hosts)

## 反馈与贡献

欢迎提交可复现的误拦截、漏拦截或构建问题。请先阅读 [反馈与贡献指南](CONTRIBUTING.md)，并使用 GitHub Issues 中对应的反馈模板。规则变更须有可复核证据，不以单纯增加域名数量作为目标。

## 许可

项目代码采用 [GPL-3.0](LICENSE)。本项目基于 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 派生；上游规则保留各自原有归属及许可条件。无法确认再分发条件的来源不纳入正式构建。
