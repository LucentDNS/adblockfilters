# AdBlock DNS

自动聚合、去重并编译广告与跟踪拦截规则，每 8 小时更新一次。

本项目基于 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 派生，独立维护规则源、DNS 有效性验证及多客户端构建流程。项目不以逐条复刻上游结果为目标；规则差异通过审计追踪。

## 订阅地址

优先使用原始订阅链接。所有文件均由构建流程生成并发布至 [GitHub Releases](https://github.com/LucentDNS/adblockfilters/releases/tag/rule) 与 [dist 分支](https://github.com/LucentDNS/adblockfilters/tree/dist)。

| 客户端 / 格式 | Full | Lite |
|---|---|---|
| AdGuard DNS / AdGuard Home | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnslite.txt) |
| AdGuard 浏览器扩展（基础规则） | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilters.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilterslite.txt) |
| InviZible Pro DNSCrypt | [拦截](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomain.txt) · [放行](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainallow.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainlite.txt) |
| DNSMasq | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasq.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasqlite.txt) |
| SmartDNS | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdns.conf) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdnslite.conf) |
| Shadowrocket（规则集） | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclash.list) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclashlite.list) |
| Shadowrocket（模块） | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocket.sgmodule) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocketlite.sgmodule) |
| Quantumult X | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqx.conf) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqxlite.conf) |
| Mihomo（YAML） | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.yaml) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.yaml) |
| Mihomo（MRS） | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.mrs) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.mrs) |
| Hosts | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhosts.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhostslite.txt) |
| sing-box（JSON） | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.json) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.json) |
| sing-box（SRS） | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.srs) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.srs) |
| Loon | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloon.list) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloonlite.list) |
| Surge | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurge.list) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurgelite.list) |
| MosDNS | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdns.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdnslite.txt) |
| V2Ray / Xray | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2ray.dat) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2raylite.dat) |

**Lite** 为精简版本，适合希望降低规则体积的用户；不同客户端的规则语法与匹配行为以各客户端文档为准。AdGuard 浏览器扩展可同时使用基础规则与 [浏览器补充规则](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilters.txt)。

## 规则维护

规则源定时同步、合并去重，并通过多上游 DNS 一致性验证及关键域名回归检查。DNS 验证结果不确定时不会据此删除规则。构建、来源及差异审计见 [audit Release](https://github.com/LucentDNS/adblockfilters/releases/tag/audit)。

## 来源与许可

本项目使用并致谢以下公开规则源：[AdGuard](https://github.com/AdguardTeam/AdguardFilters)、[AdRules](https://github.com/Cats-Team/AdRules)、[CJX's Annoyance List](https://github.com/cjx82630/cjxlist)、[EasyList](https://easylist.to/)、[EasyList China](https://github.com/easylist/easylist)、[EasyPrivacy](https://github.com/easylist/easylist)、[xinggsf](https://github.com/xinggsf/Adblock-Plus-Rule)、[jiekouAD](https://github.com/damengzhu/banad)、[AWAvenue Ads Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)、[HaGeZi](https://github.com/hagezi/dns-blocklists)、[OISD](https://oisd.nl/)、[StevenBlack hosts](https://github.com/StevenBlack/hosts)。

项目代码遵循 [GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.html)。上游规则分别遵循其原始许可证及使用条款。
