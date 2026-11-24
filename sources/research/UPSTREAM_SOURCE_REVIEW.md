# 上游规则源审查记录

> 本文件记录来源选择依据，不把来源数量或规则数量当作质量指标。未完成逐条解析和实测的来源，不标记为“已验证低误杀”。

## 当前清单的结构性问题

当前清单混合了三种不同用途的来源：
- DNS 专用来源：AdGuard DNS filter、AdRules DNS List、AWAvenue Ads Rule、HaGeZi DNS-Blocklists PRO mini、OISD Basic。
- 浏览器内容过滤来源：AdGuard Base、AdGuard Chinese、AdGuard Mobile Ads、EasyList、EasyList China、EasyPrivacy、CJX's Annoyance List、xinggsf mv、jiekouAD。
- Hosts 来源：StevenBlack hosts。

它们不能只按文件行数或域名数量横向比较。浏览器规则包含 URL、元素隐藏、脚本规则等语法；DNS 列表主要表达域名级拦截。把它们全部提取成域名集合，会丢失规则语义。

## 已核实的来源关系

### AdGuard DNS filter 与其组成来源

AdGuard 官方说明，AdGuard DNS filter 是为 DNS 级过滤简化的组合列表，组成部分包括 AdGuard Base、Social media、Spyware、Mobile Ads、EasyList 和 EasyPrivacy。

当前项目同时订阅 AdGuard DNS filter，以及 AdGuard Base、AdGuard Mobile Ads、EasyList、EasyPrivacy 等组成来源。这存在明显的来源重叠，但不能简单删除 AdGuard DNS filter：它可能包含 Social media、Spyware 等当前清单未单独列出的内容，而且它经过 DNS 兼容性处理。

**处理结论：暂时保留，不在没有逐条规则差异报告前贸然删除。** 后续应下载同一构建时点的源文件，按规则语义计算重复、独有和冲突规则，再决定采用“DNS 专用聚合源”还是“拆分后的可控来源”。

### HaGeZi 与 OISD

HaGeZi 官方将 Light、Normal、Pro、Pro++、Ultimate 定义为不同强度的主列表，并明确建议主列表只选一个层级；Mini 是对应层级的体积优化版本，不应与其完整版本叠加。

当前使用的是 Pro mini，不是同时叠加 HaGeZi Pro 完整版。OISD Basic 是另一套聚合来源，与 HaGeZi 可能有大量重叠，但不能仅凭两者定位相似就认定冗余。

**处理结论：暂时保留，要求后续输出来源交集率、独有规则量和误拦截反馈证据；不能把两个列表的简单并集当作质量提升。**

### AdRules DNS List

AdRules 项目明确区分内容过滤规则与 DNS 规则，并提供多种 DNS 格式。当前引用的是其 DNS 规则 dns.txt，来源类型与目标用途匹配。

**处理结论：保留为中国地区 DNS 来源候选；继续监测更新状态、规则变化和白名单回归。**

### AWAvenue Ads Rule

AWAvenue 官方文档说明其域名规则按域名过滤，不能精确区分同一域名下的广告与正常内容；项目同时提供多种不同格式，不能混用。

**处理结论：只保留当前 AdGuard 兼容的 DNS/域名版本；不把 hosts、Dnsmasq、SmartDNS 等其他格式误当作同一规则文件。**

### StevenBlack hosts

StevenBlack 的基础 hosts 列表面向广告、恶意软件、跟踪等用途，并提供可选扩展类别。当前引用基础 hosts 文件，不应将其可选社交、博彩等扩展误算为基础规则。

**处理结论：暂时保留基础 hosts；后续按规范化域名集合与其他来源比较贡献，不启用无关扩展。**

### xinggsf mv

上游文件是面向 uBlock Origin / AdGuard 扩展的视频过滤规则，不是 DNS 专用列表。将其中可识别的域名提取到 DNS 输出，并不意味着视频广告可以通过 DNS 完整拦截。

**处理结论：仅作为浏览器内容规则来源保留；不得将它计入 DNS 规则覆盖能力。**

## 2026-11-24 已执行的构建分类调整

- **AdGuard DNS filter**：来源表类型由 `filter` 改为 `dnsfilter`，继续保留并进入 DNS 域名构建。
- **AdRules DNS List**：来源表类型由 `filter` 改为 `dnsfilter`，继续保留并进入 DNS 域名构建。
- **普通浏览器 filter 来源**：不删除来源，但不再把其启发式提取出的域名并入 DNS 规则；其原始过滤规则仍进入浏览器补充过滤输出。
- 本轮没有新增或删除上游来源。以上为类型和构建通道调整，不是把来源误报为新增或删除。

## 当前暂不执行的删除

- 不因来源间有交集就直接删除其中一个来源。
- 不因来源更新日期较旧就直接判定停止维护；应检查上游仓库实际提交、文件版本和下载状态。
- 不把浏览器过滤语法转换得到的域名数量算作 DNS 规则有效拦截量。
- 不删除白名单、黑名单、原始源文件和构建审计数据。

## 下一步必须补齐的技术工作

1. 为每个来源单独保存原始快照、下载时间、上游版本/提交信息和文件哈希。
2. 使用与最终编译相同的解析器，逐来源统计可解析规则、无法解析规则、DNS 可用域名和浏览器专用规则。
3. 输出两两交集、来源独有规则、冲突规则及白名单命中情况。
4. 按用途分离 DNS 输出与浏览器内容过滤输出，避免把浏览器规则误算成 DNS 拦截能力。
5. 在差异报告和回归检查通过后再调整来源；任何删除都保留来源、理由和前后产物对比。

## 参考依据

- AdGuard DNS filter 组成说明：https://github.com/AdguardTeam/AdGuardSDNSFilter
- AdGuard 官方过滤器组成说明：https://adguard.com/kb/general/ad-filtering/adguard-filters/
- AdGuard Filters Registry 来源接纳与维护政策：https://github.com/AdguardTeam/FiltersRegistry
- HaGeZi 主列表层级与 Mini 说明：https://github.com/hagezi/dns-blocklists/blob/main/README.md
- HaGeZi 列表组合 FAQ：https://github.com/hagezi/dns-blocklists/blob/main/FAQ.md
- AdRules 项目及格式说明：https://github.com/Cats-Team/AdRules
- AWAvenue 格式与适用范围说明：https://github.com/AWAvenue/AWAvenueAdsWebSite
- StevenBlack 基础 hosts 与扩展说明：https://github.com/StevenBlack/hosts
- xinggsf mv 文件用途说明：https://github.com/xinggsf/Adblock-Plus-Rule