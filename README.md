# AdBlock DNS Filters

去广告合并规则，基于原作者 217heidai/adblockfilters 项目持续维护。保留原项目的规则组织方式、订阅格式和核心处理思路；在此基础上进行必要的来源审查、DNS 验证及构建质量检查。

## 说明

1. 定时从上游各规则源获取更新，合并去重。
2. 使用国内、国外 DNS 服务对上游各规则源拦截的域名进行解析，去除已确认无法解析的域名。（上游各规则源中存在大量已无法解析的域名，无需加入拦截规则）
3. 遵循原项目原则，以合并、去重和无效域名筛选为主；任何额外处理均应有明确依据，并经过验证，避免随意修改上游规则含义。
4. 规则文件通过 GitHub Releases 和 dist 分支分发，请根据网络情况选择可用订阅地址。

## DNS 订阅

| 版本 | 地址 |
|---|---|
| DNS 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt |
| DNS Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnslite.txt |

规则 x’ 为规则 x 的 Lite 版，仅针对国内域名拦截，体积较小（如添加完整规则报错数量限制，请尝试 Lite 规则）。AdGuard 等浏览器插件使用规则 1 + 规则 2，规则 2 为规则 1 的补充，仅适用于浏览器插件。

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
- 误拦截修正须经复现与回归验证；未经验证不直接扩大白名单范围。

## License

GPL-3.0. 上游规则遵循各自原始许可证及使用条款。
