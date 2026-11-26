# AdBlock DNS

自动聚合、去重并编译广告与跟踪拦截规则，每日自动更新一次。

本项目基于 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 派生，独立维护规则源、DNS 有效性验证及多客户端构建流程。项目不以逐条复刻上游结果为目标；规则差异通过审计追踪。

## 支持的客户端与订阅

目前提供 **17 类客户端 / 格式集成、35 个正式订阅文件**，支持 Full 与 Lite 两种版本（InviZible Pro 另提供独立放行列表）。优先使用原始订阅链接。所有文件均由构建流程生成并发布至 [GitHub Releases](https://github.com/LucentDNS/adblockfilters/releases/tag/rule) 与 [dist 分支](https://github.com/LucentDNS/adblockfilters/tree/dist)。

| 客户端 / 格式 | Full | Lite |
|---|---|---|
| AdGuard DNS / AdGuard Home | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnslite.txt) |
| AdGuard 浏览器扩展（补充规则） | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilters.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilterslite.txt) |
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

**Lite** 为精简版本，适合希望降低规则体积的用户；不同客户端的规则语法与匹配行为以各客户端文档为准。AdGuard 浏览器扩展建议将 AdGuard DNS 规则与对应的浏览器补充规则组合使用。

## 规则维护

规则源定时同步、合并去重，并通过多上游 DNS 一致性验证及关键域名回归检查。DNS 验证结果不确定时不会据此删除规则。构建、来源及差异审计见 [audit Release](https://github.com/LucentDNS/adblockfilters/releases/tag/audit)。

## 反馈与贡献

欢迎报告可复现的误拦截、漏拦截和构建问题。提交前请阅读 [反馈与贡献指南](CONTRIBUTING.md)。请通过 GitHub Issues 中的误拦截和漏拦截专用表单提交反馈。

每项规则变更都应有可复核证据；不会仅凭域名名称或单条主观反馈直接扩大拦截范围。

## 集成的上游规则源

当前构建集成 **11 个上游规则源**。下表列出实际使用的来源及订阅地址；来源清单以仓库根目录的 `sources.json` 为准。

| 上游项目 / 规则 | 类型 | 实际使用的规则地址 |
|---|---|---|
| AdGuard Base filter | 浏览器过滤 | [filter.txt](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt) |
| AdGuard Chinese filter | 浏览器过滤 | [filter.txt](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt) |
| AdGuard Mobile Ads filter | 浏览器过滤 | [adservers.txt](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt) |
| AdGuard DNS filter | DNS 过滤 | [filter.txt](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt) |
| CJX's Annoyance List | 浏览器过滤 | [cjx-annoyance.txt](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt) |
| EasyList | 浏览器过滤 | [easylist.txt](https://easylist-downloads.adblockplus.org/easylist.txt) |
| EasyList China | 浏览器过滤 | [easylistchina.txt](https://easylist-downloads.adblockplus.org/easylistchina.txt) |
| EasyPrivacy | 浏览器过滤 | [easyprivacy.txt](https://easylist-downloads.adblockplus.org/easyprivacy.txt) |
| AWAvenue Ads Rule (Only.Ads) | DNS 规则 | [Only.Ads](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Adguard-Only.Ads.txt) |
| HaGeZi DNS-Blocklists (Pro Mini) | DNS 规则 | [pro.mini.txt](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt) |
| StevenBlack hosts | Hosts | [hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts) |

其中“浏览器过滤”来源用于生成浏览器补充规则；DNS 过滤和 Hosts 来源参与域名规则构建。实际纳入范围、类型及更新地址以 `sources.json` 为准，来源的上游归属不会因聚合而改变。

## 许可与归属

本项目基于 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 派生，并在此基础上独立维护来源清单、DNS 有效性验证、规则处理和多客户端构建流程。感谢上述 11 个上游规则项目的维护者。

项目代码遵循 [GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.html)。各上游规则分别遵循其原始许可证及使用条款；对无法核实许可证或再分发条件的来源，不纳入正式构建。
