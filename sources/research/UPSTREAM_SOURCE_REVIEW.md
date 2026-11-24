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


### Pollock hosts（候选审计，不集成）

原作者的当前来源表还包含 Pollock hosts，官方文件由 Dan Pollock 维护，文件头标注 2026-11-22 更新，覆盖广告、间谍软件、跟踪和部分恶意站点。为避免漏审，本项目将其作为**候选源单独审计**，但不加入生产来源表。

同解析器结果：13,116 个可解析拦截域名；与现有正式来源比较后，只有 **2 个**父级压缩后独有覆盖候选，13,114 个已被现有来源的相同域名或父域名覆盖。边际收益极低，因此不集成。候选源只出现在审计报告中，不参与正式来源交集、规则编译或订阅发布。

官方来源：https://someonewhocares.org/hosts/hosts

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

## 白名单解析修正

2026-11-24 修正 `__getWhiteDict`：支持纯域名及 `||domain^$options` 形式，提取域名后再构建白名单集合；包含路径、通配符、元素隐藏语法的条目不再送入公共后缀解析器当作域名。新增测试覆盖根域名例外、子域名例外和非域名规则。

2026-11-24 进一步修正白名单覆盖：若白名单域名被某条父级 DNS 拦截规则覆盖，则自动生成对应的 `@@||白名单域名^` 放行例外；仅在确实存在父级覆盖时添加，避免无意义地扩大例外规则。回归测试覆盖 `cdn.branch.io` 被 `branch.io` 覆盖的场景。

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


## 2026-11-24 逐源 DNS 贡献审计与 AWAvenue 变体选择

本轮使用仓库当前 Resolver 对 6 个 DNS/Hosts 来源的同一轮下载快照逐源解析；6 个来源全部下载成功。统计只针对可解析的 block 域名，不把浏览器过滤语法提取的域名混入 DNS 覆盖。

| 来源 | 可解析拦截域名 | 父级压缩后独有覆盖候选 | 决策 |
|---|---:|---:|---|
| AdGuard DNS filter | 193,466 | 8,419 | 保留。官方 DNS 专用聚合源，仍有独立覆盖 |
| AdRules DNS List | 214,254 | 19,364 | 保留。与 AdGuard DNS 高度重合，但仍有明显独立覆盖 |
| AWAvenue Ads Rule (Only.Ads) | 651 | 7 | 保留纯广告变体；其中 a0.app.xiaomi.com 已在白名单，pay.sboot.cn 本轮新增白名单，剩余约 5 个独有候选 |
| HaGeZi DNS-Blocklists PRO mini | 98,219 | 50,764 | 保留。独立覆盖贡献最大，使用 Pro mini 单一层级 |
| OISD Basic（当前 URL 实际返回 oisd small） | 62,659 | 2,242 | 保留观察。边际覆盖较小，但该变体以广告为主，且持续维护 |
| StevenBlack hosts | 81,675 | 20,753 | 保留基础 hosts；另有 21,882 个子域条目被本来源自身父域名覆盖，可由最终父级压缩消除 |

全来源合并后的唯一拦截域名为 357,761 个；跨来源精确重复域名为 204,526 个。AdGuard DNS filter 与 AdRules DNS List 两两重合 179,653 个，但两者仍分别贡献 8,419 和 19,364 个父级压缩后独有候选，因此不能只因重合度高就删除其中之一。

### AWAvenue 变体调整

AWAvenue 自 1.7.6 起将规则拆分为广告、隐私、不受欢迎三类，并提供 Only.Ads、No.Privacy、No.Unwelcome 变体。为避免把隐私上报、强制更新或 PCDN 等非广告功能规则一并当作广告拦截，本项目改用作者的 AdGuard Only.Ads 文件：

`https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Adguard-Only.Ads.txt`

与默认混合版相比，当前解析器识别的拦截域名由 978 降至 651，减少 327 个。该变体仍有 4 条带通配符的规则无法作为普通 DNS 域名规则解析；这些条目不会被猜测性转换或混入 DNS 输出。

### 白名单复核

- `a0.app.xiaomi.com`：已存在于项目白名单，不会进入最终拦截。
- `pay.sboot.cn`：新增白名单，避免影响长虹电视支付功能。
- AWAvenue Only.Ads 不再包含此前混合版中的 `tnc3-aliec1.toutiaoapi.com`、`api.statsig.com`、`mobile.events.data.microsoft.com` 等候选，因此本轮不需要为这些域名新增例外。

### 重复与未识别条目处理

- 完全相同的域名在构建器中按集合合并，最终输出只保留一份；保留上游原始来源和审计数据以便追溯，不通过破坏原始来源文件来“去重”。
- 父域名已覆盖的子域名按最终父级压缩逻辑消除。StevenBlack 本来源内有 21,882 个子域条目可由其自身父域名覆盖。
- AdRules 的 4 条未识别候选为 `localhost.localdomain` 及 3 条无公共后缀的 `tnc3-*.zijieapi` 名称；AWAvenue 的 4 条未识别候选为通配符模式；StevenBlack 的 15 条未识别候选为 localhost、loopback、broadcast 等本机/保留地址记录。均不凭猜测生成 DNS 域名规则。
- 上述独有覆盖统计尚未扣除项目黑名单、白名单和上游 allow 例外，属于来源贡献上限估计，不代表每一条都已经完成误杀验证。

### 本轮来源决策

本轮没有新增或删除来源。保留 6 个来源，但将 AWAvenue 从默认混合版调整为 Only.Ads 变体；为已知功能域名补充白名单。当前数据不支持仅凭重复比例删除 AdGuard DNS、AdRules、HaGeZi、OISD 或 StevenBlack 中的任何一个。OISD 与 AWAvenue 的边际贡献较小，列入后续反馈观察，不盲目扩展来源数量。

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