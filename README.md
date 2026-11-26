# AdBlock DNS
去广告合并规则，每 8 小时更新一次。
本项目聚合多个公开维护的广告、跟踪及浏览器过滤规则源，自动更新、去重并生成适配多种客户端的 Full/Lite 规则。

本仓库从 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 派生，遵循上游许可证并保留来源追溯。项目独立维护上游源集合、DNS 验证策略、手工规则证据、客户端格式编译与发布流程；不以逐条复刻上游输出为目标，所有差异均纳入审计。

## 说明
1. 定时从上游各规则源获取更新，合并去重。
2. 使用 5 个独立、非拦截 DNS 上游（国内 2 个、国际 3 个），每个上游使用独立监听端口，不做最快响应池化。只有 5 个上游对 A、AAAA 查询全部返回 NXDOMAIN，才将域名判为失效并剔除；NODATA、超时、SERVFAIL、上游缺失或任何结果不一致均不会作为删除依据。
3. 本项目以合并、去重和去除经五上游 DNS 一致确认的无效域名为主，不随意改写上游规则语义；myblock.txt（补充拦截及浏览器例外）仅保留有可复现证据的项目自维护拦截和必要的浏览器路径例外，不因旧基线存在就直接导入未经验证的域名；white.txt（误拦截放行例外）单独管理。所有项目规则均纳入来源校验与误拦截回归检查。误拦截修正以可复现证据为准，优先使用精确主机或路径例外，避免扩大父域名放行范围。
4. 规则文件托管于 GitHub Releases 和 dist 分支，加速通道为 gh-proxy.com / ghfast.top / ghproxy.net，请根据网络情况选择可用订阅地址。

## 正式订阅（仅列出构建验证通过的产物）

1. 规则1' 为规则1的 Lite 版，依据五个独立 DNS 上游验证的国内域名集合筛选；AdGuard DNS Lite 沿用 `||domain^` 语义（主域名及其子域名）；其他 DNS 客户端按各自格式输出精确域名或主机匹配，体积较小。
2. AdGuard 等浏览器插件使用规则1 + 规则2（规则2为规则1的补充，仅适用于浏览器插件）。
3. 原始链接优先；加速链接由第三方提供，可能因地区、运营商或服务状态而波动。手机浏览器（Via、X）订阅失败时请改用原始链接。

| 规则 | 原始链接 | 加速链接1 | 加速链接2 | 加速链接3 | 适配说明 |
|:-|:-|:-|:-|:-|:-|
| 规则1 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt) | AdGuard、AdGuard Home 等 |
| 规则1' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnslite.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnslite.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnslite.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnslite.txt) | AdGuard、AdGuard Home 等 |
| 规则2 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilters.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilters.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilters.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilters.txt) | AdGuard 等浏览器插件 |
| 规则2' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilterslite.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilterslite.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilterslite.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilterslite.txt) | AdGuard 等浏览器插件 |
| 规则3 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomain.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomain.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomain.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomain.txt) | InviZible Pro DNSCrypt |
| 规则3' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainlite.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainlite.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainlite.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainlite.txt) | InviZible Pro DNSCrypt |
| 规则3 allowlist | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainallow.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainallow.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainallow.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdomainallow.txt) | InviZible Pro DNSCrypt allowed_names_file; use with the blocklist |
| 规则4 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasq.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasq.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasq.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasq.txt) | DNSMasq |
| 规则4' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasqlite.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasqlite.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasqlite.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnsmasqlite.txt) | DNSMasq |
| 规则5 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdns.conf) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdns.conf) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdns.conf) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdns.conf) | SmartDNS |
| 规则5' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdnslite.conf) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdnslite.conf) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdnslite.conf) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksmartdnslite.conf) | SmartDNS |
| 规则6 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclash.list) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclash.list) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclash.list) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclash.list) | Shadowrocket |
| 规则6' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclashlite.list) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclashlite.list) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclashlite.list) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockclashlite.list) | Shadowrocket |
| 规则7 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocket.sgmodule) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocket.sgmodule) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocket.sgmodule) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocket.sgmodule) | Shadowrocket Module |
| 规则7' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocketlite.sgmodule) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocketlite.sgmodule) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocketlite.sgmodule) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockshadowrocketlite.sgmodule) | Shadowrocket Module |
| 规则8 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqx.conf) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqx.conf) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqx.conf) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqx.conf) | Quantumult X |
| 规则8' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqxlite.conf) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqxlite.conf) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqxlite.conf) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockqxlite.conf) | Quantumult X |
| 规则9 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.yaml) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.yaml) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.yaml) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.yaml) | Mihomo |
| 规则9' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.yaml) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.yaml) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.yaml) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.yaml) | Mihomo |
| 规则10 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.mrs) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.mrs) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.mrs) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomo.mrs) | Mihomo |
| 规则10' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.mrs) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.mrs) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.mrs) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmihomolite.mrs) | Mihomo |
| 规则11 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhosts.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhosts.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhosts.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhosts.txt) | Hosts / personalDNSfilter |
| 规则11' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhostslite.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhostslite.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhostslite.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockhostslite.txt) | Hosts / personalDNSfilter |
| 规则12 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.json) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.json) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.json) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.json) | sing-box 1.12+ |
| 规则12' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.json) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.json) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.json) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.json) | sing-box 1.12+ |
| 规则13 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.srs) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.srs) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.srs) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingbox.srs) | sing-box 1.12+ |
| 规则13' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.srs) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.srs) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.srs) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksingboxlite.srs) | sing-box 1.12+ |
| 规则14 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloon.list) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloon.list) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloon.list) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloon.list) | Loon |
| 规则14' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloonlite.list) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloonlite.list) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloonlite.list) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockloonlite.list) | Loon |
| 规则15 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurge.list) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurge.list) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurge.list) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurge.list) | Surge |
| 规则15' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurgelite.list) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurgelite.list) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurgelite.list) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblocksurgelite.list) | Surge |
| 规则16 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdns.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdns.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdns.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdns.txt) | MosDNS |
| 规则16' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdnslite.txt) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdnslite.txt) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdnslite.txt) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockmosdnslite.txt) | MosDNS |
| 规则17 | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2ray.dat) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2ray.dat) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2ray.dat) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2ray.dat) | V2Ray / Xray |
| 规则17' | [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2raylite.dat) | [加速链接1](https://gh-proxy.com/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2raylite.dat) | [加速链接2](https://ghfast.top/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2raylite.dat) | [加速链接3](https://ghproxy.net/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockv2raylite.dat) | V2Ray / Xray |

## 上游来源

以下为本项目实际使用的上游源；本表仅用于来源追溯，不是客户端订阅地址。

| 来源 | 类型 | 上游地址 | 更新信息 |
|---|---|---|---|
| AdGuard Base filter | filter | [upstream](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt) | 2026/11/25 |
| AdGuard Chinese filter | filter | [upstream](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_224_Chinese/filter.txt) | 2026/11/25 |
| AdGuard Mobile Ads filter | filter | [upstream](https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt) | 2026/11/11 |
| AdGuard DNS filter | dnsfilter | [upstream](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt) | 2026/11/25 |
| AdRules DNS List | dnsfilter | [upstream](https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt) | 2026/11/25 |
| CJX's Annoyance List | filter | [upstream](https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt) | 2026/10/01 |
| EasyList | filter | [upstream](https://easylist-downloads.adblockplus.org/easylist.txt) | 2026/11/25 |
| EasyList China | filter | [upstream](https://easylist-downloads.adblockplus.org/easylistchina.txt) | 2026/11/25 |
| EasyPrivacy | filter | [upstream](https://easylist-downloads.adblockplus.org/easyprivacy.txt) | 2026/11/25 |
| xinggsf mv | filter | [upstream](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt) | 2025/12/24 |
| jiekouAD | filter | [upstream](https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt) | 2026/11/22 |
| AWAvenue Ads Rule (Only.Ads) | dns | [upstream](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Adguard-Only.Ads.txt) | 2026/11/23 |
| DNS-Blocklists PRO mini | dns | [upstream](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt) | 2026/11/25 |
| OISD Small | dns | [upstream](https://small.oisd.nl/) | 2026/11/25 |
| StevenBlack hosts | host | [upstream](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts) | 2026/11/24 |

## 维护与反馈

- 规则产物由 GitHub Actions 每 8 小时自动构建；DNS 验证状态每日更新，完成关键服务域名及白名单回归检查后，发布在 dist 分支及 Releases。
- 构建审计、来源贡献及与上游基线的差异报告见 audit Release。规则数量差异不等同于质量优劣证明。
- 误拦截修正须经复现与回归验证；未经验证不直接扩大白名单范围。

## 本地开发与验证

在仓库根目录执行以下命令，安装运行依赖和开发依赖，并运行与 CI 一致的静态检查及回归测试：

```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m ruff check --no-cache .
python -m ruff check --no-cache --select F401 scripts tests
python -m ruff check --no-cache --select E4,E7,E9,F scripts tests readme.py
python -m pytest -q tests
```

DNS 状态验证、规则编译及 Release/dist 发布由 GitHub Actions 执行；本地测试通过不等于生产产物已发布。

## License

GPL-3.0. 上游规则遵循各自原始许可证及使用条款。
