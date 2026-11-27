# AdBlock DNS

自动聚合、清理并编译 AdGuard DNS / AdGuard Home 规则及 AdGuard 浏览器补充规则，每日自动更新一次。

本项目基于 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 派生，独立维护规则来源、DNS 验证、审计与构建流程。

## 项目状态与使用提示

本项目是持续验证中的独立规则项目，仍处于早期完善阶段。每日生产构建执行上游来源检查、规则解析与清洗、来源异常熔断、AdGuard DNS 语法编译校验、关键服务域名与白名单回归；每周另有独立 DNS 诊断工作流，用于观察解析状态，不参与每日规则决策，也不作为正式发布门槛。这些检查只能降低部分风险，不能保证所有网站、应用和设备均无误拦截或漏拦截。**上游规则源的接入不代表逐条人工预审，也不代表已对每条规则完成独立质量背书；项目没有覆盖所有域名的前置自动误报扫描。** 自动化检查不能证明每条规则都不会影响正常业务，也不能替代真实设备与实际使用场景验证。误报主要依赖用户提供可复现证据后逐项核实。

项目没有预先批量添加通用放行域名。首次使用或用于重要设备时，建议先观察一段时间，并确认所用客户端支持相应规则格式。遇到网站、应用或系统功能异常，请提交可复现的反馈；项目不承诺零误报或零漏报，也不会仅凭未经验证的单次反馈直接放行域名。

## 订阅

提供 **Full** 与 **Lite** 两种版本，共 4 个正式订阅文件。建议使用下表中的 Raw 链接。

| 目标产品 | Full | Lite |
|---|---|---|
| AdGuard DNS / AdGuard Home | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnslite.txt) |
| AdGuard 浏览器扩展（补充规则） | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilters.txt) | [订阅](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockfilterslite.txt) |

正式规则构建不执行全量 DNS 存活性筛选，也不会因 NXDOMAIN、NODATA、超时或 SERVFAIL 自动删除上游作者维护的规则。Full 保留经来源解析、语法兼容、冲突与白名单治理后的规则；Lite 只按明确的国内分类数据选择已有 DNS 规则。DNS 解析状态不等于规则价值：域名暂时不可解析，不代表它不再需要拦截；语法校验也不等于误报判断。

- **Full**：包含所选上游 DNS/Hosts 来源经解析、规范化、冲突处理与白名单治理后保留的完整规则范围，不按 DNS 存活状态删减上游规则。
- **Lite**：DNS 域名规则按 `.cn` 域名及国内直连域名规则（`full:`、`domain:`）进行保守分类，不依赖全量 DNS 存活验证。分类数据来自 [217heidai RoutingRules direct.txt](https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/direct.txt)，仅作国内范围识别，不作为广告拦截规则来源。未被分类为国内的域名不会自动当作失效规则删除。浏览器过滤规则按规则关联域名及规则自身匹配范围筛选，并保留原有匹配语义。

浏览器过滤规则中的元素隐藏、脚本注入、修饰符等语法不等同于 DNS 拦截规则。本项目将浏览器过滤规则与 DNS 域名规则分开处理；请勿把浏览器订阅导入仅支持 DNS 域名的网关，也不要期待 DNS 订阅执行网页元素或脚本过滤。DNS Full/Lite 使用 AdGuard Home 的 Adblock-style 域名语法（例如 `||example.com^`、`@@||example.com^`），每次构建都会使用 AdGuard 官方 [Hostlist Compiler](https://github.com/AdguardTeam/HostlistCompiler) v2.1.1 对两个 DNS 产物执行 `Validate` 与 `Deduplicate` 独立校验；如果编译器移除或改写拦截规则，或发现重复规则，校验就会失败，阻止本轮正式发布；独立且在当前列表内冗余的放行例外可被编译器规范化移除，但正式订阅仍保留原始放行规则。**这项检查验证的是 DNS 列表语法和编译器兼容性，不代表自动判断了域名是否真是广告/跟踪，也不代表已经排除了误拦截。** 请按客户端支持的格式导入；不同客户端的匹配行为以其自身文档为准。规则编写参考 [AdGuard 官方指南](https://adguard.com/kb/general/ad-filtering/create-own-filters/)。DNS 主机名规则只保留作用范围固定在已知注册域名之下的模式；通配注册域/TLD 的宽泛模式、正则规则，以及需要特殊上下文或规则集级处理的修饰符不进入 DNS 输出。对于 AdGuard Home 支持且可原样保留的 `$dnstype`，项目保留原始规则及其记录类型限制，不将其改写成无条件拦截。通配模式不是可直接查询的完整域名，因此不做 A/AAAA 存活性探测，只接受语法校验；Lite 仅保留其固定注册域名命中国内分类集合的模式。通配模式只输出到 AdGuard DNS Full/Lite 订阅；浏览器补充规则则保留其自身支持的过滤语法。

## 白名单与误报处理

项目维护的独立白名单位于 [rules/white.txt](rules/white.txt)，用于排除有证据支持的正常业务域名误拦截。白名单会参与规则处理，并对 Full 与 Lite 产物执行回归检查；它不是广告规则源，也不应被当作通用放行列表。

白名单采用证据驱动策略：没有足以核实误拦截的有效证据，不添加放行规则。新增或修改条目时，应记录证据链接或脱敏日志摘要、受影响应用/网站与客户端、复现条件、核实日期及放行范围；优先使用精确主机名，避免无必要地放行整个主域名。仅有“网站打不开”或单次解析失败，不足以证明是本项目规则误拦截。详细材料要求见 [反馈与贡献指南](CONTRIBUTING.md)。

## 规则与审计

不同作者规则集的差异不会通过简单并集或多数表决自动解决。当前正式 DNS/Hosts 来源的显式 allow 是跨来源兼容例外：某个正式来源明确放行的域名，即使被另一个正式来源拦截，也会在合并后的 Full/Lite 结果中优先保留放行；这是有意偏向降低误杀风险的策略，代价是可能少拦截一部分广告或跟踪域名。候选来源的 allow 只用于对照审计，不改变正式产物；某来源没有收录某域名，也不等于它明确放行。构建审计会检查与编译拦截规则冲突的正式来源 allow 是否仍在 Full 输出中有效，缺失时阻止发布。当前将 HaGeZi Pro Mini 单独列为重点复核对象，但不把它擅自标成作者定义的“严格型”：HaGeZi 官方将 Pro 档描述为 Balanced、低至中等破坏风险；Pro Mini 是该档的精简变体。其 [来源目录](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/sources.md) 明确列出 AdGuard DNS、AWAvenue、1Hosts Lite、OISD Big、EasyList、EasyPrivacy 等构建输入。1Hosts 的 [输入/贡献目录](https://raw.githubusercontent.com/badmojr/1Hosts/master/-data/lists/assets.txt) 又列有 HaGeZi Pro、AWAvenue、StevenBlack、OISD Big；anti-AD 的 [README 致谢](https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/README.md) 提及 AWAvenue、AdGuard、EasyList 等项目，但致谢不等于当前实际集成。由此可见，来源之间存在交叉谱系，不能把来源数量或重合数量当成独立证据票数。构建审计输出重点复核来源未共享候选及其与其他来源明确放行规则的冲突。**来源未收录不等于明确放行；来源重合也不等于独立确认。** 报告只用于人工复核，不会自动把候选加入正式规则；公开资料未能证明的上游关系会明确标注为未核实。

规则源由 `sources.json` 统一维护。每日生产构建执行来源检查、去重、来源异常检查、关键域名与白名单回归，并使用 AdGuard 官方 Hostlist Compiler 校验 DNS Full/Lite 语法与规则保留情况。每周 DNS 诊断独立运行；NXDOMAIN、NODATA、超时或 SERVFAIL 不会被当作删除上游规则的依据，也不会阻塞每日正式构建。与 217heidai 基线的差异只用于覆盖范围对照，不代表误报率或整体质量等价；未被当前来源解释的差异会保留在审计报告中，不能仅凭编译成功就宣称与任何主流规则集质量相当。

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
- 1Hosts (Lite) — [来源](https://cdn.jsdelivr.net/gh/badmojr/1Hosts@master/Lite/adblock.txt)
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

项目会参考 AdGuard [HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry) 的收录实践与成熟规则集，但不以其收录目录作为待集成清单。候选源（例如 AdRules DNS、OISD Small/Big、HaGeZi 不同强度版本等）只用于评估，不会因已被官方收录或规则数量庞大而自动进入正式构建。每个来源必须证明其目标明确、维护活跃、许可允许再分发，并能相对现有来源带来有意义且可解释的增量；还需审查来源内部的误报风险、规则语义、DNS 验证结果、与现有来源的重合及白名单冲突。若增量不足、质量证据不足或许可不清晰，就不集成。正式来源的选择以互补性和整体规则质量为准，而不是来源数量。

## 反馈与贡献

欢迎提交可复现的误拦截、漏拦截或构建问题。请先阅读 [反馈与贡献指南](CONTRIBUTING.md)，并使用 GitHub Issues 中对应的反馈模板。规则变更须有可复核证据，不以单纯增加域名数量作为目标。

## 许可与归属

项目仓库级代码许可证为 [GPL-3.0](LICENSE)。这不意味着所有第三方规则数据都被统一改许可；每个上游来源仍保留其自身许可证、版权声明和再分发条件。

**完整来源许可矩阵、上游证据链接和随发布产物提供的许可证副本，见 [第三方来源许可与归属说明](THIRD-PARTY-NOTICES.md) 及机器可读的 [source-licenses.json](source-licenses.json)。** 当前正式 DNS/Hosts 来源包括 GPL-3.0、MIT 与 MPL-2.0 来源；浏览器补充来源还包括 LGPL-3.0 与 EasyList 的双许可来源。候选源不会自动并入正式订阅；CHN AdRules 的生成规则包含混合上游许可，因此只保留比较统计，不公开分发其提取域名文件。

构建流程会把适用的许可证文本和第三方归属说明一并放入 `source` 快照 Release 与 `dist` 订阅分支。来源许可发生变化时，必须同步更新许可清单并通过审计；无法确认再分发条件的来源不得加入正式发布。许可说明用于归属和合规记录，不构成法律意见。
