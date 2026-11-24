# DNS Adblock Filters

独立维护的 DNS 与浏览器内容过滤规则。上游来源经过分类、解析、去重和贡献审查；构建包含白名单回归及关键服务检查。

## DNS 订阅

| 版本 | 地址 |
|---|---|
| DNS 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt |
| DNS Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnslite.txt |

DNS Lite 适用于希望减少规则数量的场景；仅在客户端有需要时再添加浏览器补充规则。

## 其他客户端订阅

| 客户端 | 版本 | 订阅地址 |
|---|---|---|
| AdGuard 浏览器过滤 | 浏览器补充规则 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilters.txt |
| AdGuard 浏览器过滤 | 浏览器补充 Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilterslite.txt |
| InviZible Pro / personalDNSfilter | 域名全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomain.txt |
| InviZible Pro / personalDNSfilter | 域名 Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainlite.txt |
| DNSMasq | 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasq.txt |
| DNSMasq | Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasqlite.txt |
| SmartDNS | 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdns.conf |
| SmartDNS | Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdnslite.conf |
| Shadowrocket | Clash 规则全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclash.list |
| Shadowrocket | Clash 规则 Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclashlite.list |
| Shadowrocket Module | 模块全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocket.sgmodule |
| Shadowrocket Module | 模块 Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocketlite.sgmodule |
| Quantumult X | 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqx.conf |
| Quantumult X | Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqxlite.conf |
| Mihomo | YAML 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.yaml |
| Mihomo | YAML Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.yaml |
| Mihomo | MRS 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.mrs |
| Mihomo | MRS Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.mrs |
| Hosts | 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhosts.txt |
| Hosts | Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhostslite.txt |
| sing-box 1.12+ | JSON 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.json |
| sing-box 1.12+ | JSON Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.json |
| sing-box 1.12+ | SRS 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.srs |
| sing-box 1.12+ | SRS Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.srs |
| Loon | 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloon.list |
| Loon | Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloonlite.list |
| Surge | 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurge.list |
| Surge | Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurgelite.list |
| MosDNS | 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdns.txt |
| MosDNS | Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdnslite.txt |
| V2Ray / Xray | DAT 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2ray.dat |
| V2Ray / Xray | DAT Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2raylite.dat |

## 上游来源

以下为本项目实际使用的上游源；本表仅用于来源追溯，不是客户端订阅地址。

| 来源 | 类型 | 上游地址 | 更新信息 |
|---|---|---|---|
| AdGuard Base filter | filter | [upstream](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt) | 2026/11/24 |
| AdGuard Chinese filter | filter | [upstream](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt) | 2026/11/24 |
| AdGuard Mobile Ads filter | filter | [upstream](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt) | 2026/11/11 |
| AdGuard DNS filter | dnsfilter | [upstream](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt) | 2026/11/24 |
| AdRules DNS List | dnsfilter | [upstream](https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt) | 2026/11/24 |
| CJX's Annoyance List | filter | [upstream](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt) | 2026/10/01 |
| EasyList | filter | [upstream](https://easylist-downloads.adblockplus.org/easylist.txt) | 2026/11/24 |
| EasyList China | filter | [upstream](https://easylist-downloads.adblockplus.org/easylistchina.txt) | 2026/11/24 |
| EasyPrivacy | filter | [upstream](https://easylist-downloads.adblockplus.org/easyprivacy.txt) | 2026/11/24 |
| xinggsf mv | filter | [upstream](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt) | 2025/12/24 |
| jiekouAD | filter | [upstream](https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt) | 2026/11/22 |
| AWAvenue Ads Rule (Only.Ads) | dns | [upstream](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Adguard-Only.Ads.txt) | 2026/11/23 |
| DNS-Blocklists PRO mini | dns | [upstream](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt) | 2026/11/24 |
| OISD Small | dns | [upstream](https://small.oisd.nl/) | 2026/11/24 |
| StevenBlack hosts | host | [upstream](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts) | 2026/11/24 |

## 维护与反馈

- 规则产物由 GitHub Actions 每日自动构建；完成 DNS 验证、关键服务域名及白名单回归检查后，发布在 dist 分支及 Releases。
- 构建审计、来源贡献及与上游基线的差异报告见 audit Release。规则数量差异不等同于质量优劣证明。
- 如遇误拦截，请提交反馈并提供被影响的域名、客户端及复现情况；不要直接扩大白名单范围。

## License

GPL-3.0. 上游规则遵循各自原始许可证及使用条款。
