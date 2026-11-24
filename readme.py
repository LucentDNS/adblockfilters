import re
import os
from typing import List

from loguru import logger

class Rule(object):
    def __init__(self, name:str, type:str, url:str, latest:str, update:bool=False):
        self.name = name
        safe_name = re.sub(r"[^A-Za-z0-9._-]", ".", self.name.replace(' ', '_')).rstrip(".")
        self.filename = safe_name + '.txt'
        self.type = type
        self.url = url
        self.latest = latest
        self.update = update
        self.download_ok = False

# redme文件操作
class ReadMe(object):
    def __init__(self, filename:str):
        self.filename = filename
        self.ruleList:List[Rule] = []
        self.proxyList = [
            "",
            "https://gh-proxy.com",
            "https://ghfast.top",
            "https://github.boki.moe"
        ]

    def getRules(self) -> List[Rule]:
        logger.info("resolve readme...")
        self.ruleList = []
        with open(self.filename, "r") as f:
            for line in f:
                line = line.replace('\r', '').replace('\n', '')
                if line.find('|')==0 and line.rfind('|')==len(line)-1:
                    rule = list(map(lambda x: x.strip(), line[1:-1].split('|')))
                    if rule[2].find('(') > 0 and rule[2].find(')') > 0 and rule[1].find('(') < 0:
                        url = rule[2][rule[2].find('(')+1:rule[2].find(')')]
                        matchObj1 = re.match(r'(http|https)://[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)
                        if matchObj1:
                            self.ruleList.append(Rule(rule[0], rule[1], url, rule[-1]))
        return self.ruleList

    def getRulesNames(self) -> str:
        names = ""

        for rule in self.ruleList:
            names += rule.name + '、'

        return names[:-1]

    def setRules(self, ruleList:List[Rule]):
        self.ruleList = ruleList

    def __subscribeLink(self, fileName:str, tag:str, url:str=None):
        link = ""

        if tag == "rule":
            link += " [原始链接](https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/%s) |" % (fileName)

            for i in range(1, len(self.proxyList)):
                proxy = self.proxyList[i]
                link += " [加速链接%d](%s/https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/%s) |" % (i, proxy, fileName)
        else:
            if url:
                link += " [原始链接](%s) |" % (url)
            else:
                link += " [原始链接](https://github.com/LucentDNS/adblockfilters/releases/download/%s/%s) |" % (tag, fileName)

            for i in range(1, len(self.proxyList)):
                proxy = self.proxyList[i]
                link += " [加速链接%d](%s/https://github.com/LucentDNS/adblockfilters/releases/download/%s/%s) |" % (i, proxy, tag, fileName)

        return link

    def regenerate(self):
        logger.info("regenerate readme...")
        if os.path.exists(self.filename):
            os.remove(self.filename)

        with open(self.filename, 'a') as f:
            f.write("# AdBlock DNS Filters\n")
            f.write("去广告合并规则，每8个小时更新一次。  \n")
            f.write("LucentDNS 维护的 DNS 与内容过滤规则聚合项目。项目定时获取经过筛选的上游规则源，按规则类型解析、合并与去重，并生成适配多种 DNS/代理客户端的订阅文件。\n")
            f.write("\n")

            f.write("## 说明\n")
            f.write("1. 上游来源：从项目订阅表列出的规则源定时获取更新。来源会根据维护状态、规则类型、重复覆盖和实际贡献进行筛选；并非把原作者的全部来源原样照搬。\n")
            f.write("2. 域名有效性：项目通过独立维护的域名状态数据和 DNS 检测流程维护黑名单、国内域名清单等构建输入；构建时会排除黑名单中的域名。该步骤不代表对所有上游规则逐条进行实时 DNS 查询，也不能保证所有被拦截域名均无误杀。\n")
            f.write("3. 规则处理：DNS/Hosts 类条目会进行解析、归一化、合并、去重和排序，并结合黑名单、白名单及国内域名清单生成完整与 Lite 版本；浏览器过滤规则会按解析器可识别的语法处理，并与 DNS 规则去重。部分复杂过滤语法会保留原规则文本，不能把它们等同于已提取并验证的域名。项目会对上游规则做处理，不是原样镜像。\n")
            f.write("4. 质量边界：项目提供来源审计、构建结果与上游已发布 DNS 规则的集合对比及白名单回归检查。数量差异和重合度只能说明规则集合变化，不能单独证明拦截质量更好或误杀更少。遇到误拦截请先添加本地白名单（例如 `@@||www.example.com^$important`），并提交反馈以便核查。\n")
            f.write("\n")

            f.write("## 规则源调整记录\n")
            f.write("1. 2026-11-24：将 **AdGuard DNS filter**、**AdRules DNS List** 的来源类型由 `filter` 更正为 `dnsfilter`。这两项是 DNS 级规则源，现由 DNS 解析器解析并纳入 DNS 域名规则构建；这是类型纠正，不是新增或删除来源。\n")
            f.write("2. 2026-11-24：普通 `filter` 类型来源与 DNS/Hosts 来源分流。AdGuard Base、AdGuard Chinese、AdGuard Mobile Ads、CJX、EasyList、EasyList China、EasyPrivacy、xinggsf mv、jiekouAD 等浏览器规则仍保留在浏览器补充过滤构建中；不再把其启发式提取的域名混入 DNS 域名订阅。\n")
            f.write("3. 本轮未新增或删除上游来源。后续若新增、停用或删除来源，必须同步修改下方来源订阅表，并在此处记录来源名称、变更类型和理由。\n")
            f.write("4. 2026-11-24：修正白名单解析，支持纯域名及不带修饰符的 `||domain^` 形式；带 `$options` 的浏览器例外仅作为精确过滤规则处理，不会扩大为 DNS 域名白名单。路径、通配符和元素隐藏规则也不会被误当作 DNS 域名白名单。\n")
            f.write("5. 2026-11-24：补齐白名单父域名覆盖处理。若白名单子域名仍被上游父域名拦截规则覆盖，最终 DNS 规则会生成对应的 `@@||子域名^` 放行例外；自动回归检查同时检查父域名覆盖。\n")
            f.write("6. 2026-11-24：完成 6 个 DNS/Hosts 上游的同解析器逐源审计，17 个来源文件下载成功、0 失败。合并域名集合 357,756 个，跨来源精确重复 204,582 个；父级压缩后独有覆盖候选（白名单前）分别为 AdGuard DNS 8,358、AdRules DNS 19,364、AWAvenue Only.Ads 7、HaGeZi Pro mini 50,764、OISD Small 2,242、StevenBlack 20,753。该指标不等同于最终输出规则数，也不代表每条候选都已完成误杀验证。\n")
            f.write("7. 2026-11-24：AWAvenue Ads Rule 从默认的“广告+隐私+不受欢迎”混合版切换为作者提供的 AdGuard Only.Ads 纯广告变体；解析拦截域名由 978 降至 651，减少 327 个候选条目，降低非广告功能拦截风险。\n")
            f.write("8. 2026-11-24：新增 `pay.sboot.cn` 白名单例外。AWAvenue 上游更新记录说明该域名用于长虹电视支付功能，需要相关功能时应放行；`a0.app.xiaomi.com` 已由现有白名单覆盖。\n")
            f.write("9. 2026-11-24：对原作者另列的 Pollock hosts 做候选审计；13,116 个可解析拦截域名中，父级压缩后仅有 2 个独有覆盖候选，13,114 个已被现有正式来源覆盖，因此不集成。该候选仅用于审计，不进入正式订阅表或构建。\n")
            f.write("10. 2026-11-24：复核 GitHub Actions run `45377839459` 的原作者 DNS 基线差异报告：原作者基线独有 6,638 条，其中 34 条放行、6,604 条拦截。此前 README 所写 1,360 条差异与该次构建产物不符，已更正；目前仅确认 Sobot 客服平台和斗鱼网页游戏入口相关例外，其他差异仍须逐项归因，不宣称已全部审核。\n")
            f.write("11. 2026-11-24：GitHub Actions run `45377839459` 的实际比较结果为：原作者基线 255,960 条、NobleDNS 253,380 条、共有 249,322 条、NobleDNS 独有 4,058 条、原作者独有 6,638 条（34 条放行、6,604 条拦截）。该集合差异不等于质量提升；在完成逐项归因和回归验证前，不将其描述为优于原作者的正式版。\n")
            f.write("12. 2026-11-24：正式构建（GitHub Actions run `45405182096`，attempt 2）通过 47 项单元测试、45 个关键服务根域名回归、白名单回归及 Sing-box / Mihomo / V2Ray-Xray 格式编译，并成功发布到 `rule`、`source`、`audit`、`domain` Releases 和 `dist` 分支。DNS 输出 271,158 条（270,970 条拦截域名、188 条放行域名），低于 500,000 条上限。与原作者基线 255,960 条比较：共有 250,411 条、LucentDNS 独有 20,747 条、基线独有 5,549 条。来源审计覆盖 6 个 DNS/Hosts 来源和 9 个浏览器补充来源，17 个来源文件下载成功、0 失败；正式来源合并唯一域名 357,756 个，跨来源重复 204,582 个。基线差异只用于覆盖与风险核查，不据数量宣称优于原作者；仍有 9 条基线独有域名未由当前来源解释，未盲目补入，当前输出不拦截这些域名。详细数据见 `audit` Release。\n")
            f.write("\n")

            f.write("## 订阅链接\n")
            f.write("所有“规则订阅”均由 LucentDNS 自己的 `dist` 分支或 Releases 提供；不会把 217heidai 或其他上游作者的成品规则地址当作本项目订阅地址。下方“上游规则源”一节列出的原作者链接仅用于标明规则来源，不是本项目的订阅入口。\n")
            f.write("1. 规则x’为规则x的 Lite 版，仅针对国内域名拦截，体积较小（如添加完整规则报错数量限制，请尝试 Lite 规则）\n")
            f.write("2. AdGuard 浏览器扩展可按需同时使用规则1（DNS 域名规则）和规则2（补充的浏览器过滤规则）；仅使用 DNS 过滤的场景通常只需规则1。\n")
            f.write("\n")
            tmp = "| 规则 | 原始链接 |"
            for i in range(1, len(self.proxyList)):
                tmp += " 加速链接%d |" % (i)
            tmp += " 适配说明 |\n"
            f.write(tmp)
            tmp = "|" + ":-|" * ( 2 + len(self.proxyList)) + "\n"
            f.write(tmp)
            f.write("| 规则1 |" + self.__subscribeLink("adblockdns.txt", "rule") + " AdGuard、AdGuard Home 等 |\n")
            f.write("| 规则1' |" + self.__subscribeLink("adblockdnslite.txt", "rule") + " AdGuard、AdGuard Home 等 |\n")
            f.write("| 规则2 |" + self.__subscribeLink("adblockfilters.txt", "rule") + " AdGuard 等 |\n")
            f.write("| 规则2' |" + self.__subscribeLink("adblockfilterslite.txt", "rule") + " AdGuard 等 |\n")
            f.write("| 规则3 |" + self.__subscribeLink("adblockdomain.txt", "rule") + " InviZible Pro、personalDNSfilter |\n")
            f.write("| 规则3' |" + self.__subscribeLink("adblockdomainlite.txt", "rule") + " InviZible Pro、personalDNSfilter |\n")
            f.write("| 规则4 |" + self.__subscribeLink("adblockdnsmasq.txt", "rule") + " DNSMasq |\n")
            f.write("| 规则4' |" + self.__subscribeLink("adblockdnsmasqlite.txt", "rule") + " DNSMasq |\n")
            f.write("| 规则5 |" + self.__subscribeLink("adblocksmartdns.conf", "rule") + " SmartDNS |\n")
            f.write("| 规则5' |" + self.__subscribeLink("adblocksmartdnslite.conf", "rule") + " SmartDNS |\n")
            f.write("| 规则6 |" + self.__subscribeLink("adblockclash.list", "rule") + " Shadowrocket |\n")
            f.write("| 规则6' |" + self.__subscribeLink("adblockclashlite.list", "rule") + " Shadowrocket |\n")
            f.write("| 规则7 |" + self.__subscribeLink("adblockshadowrocket.sgmodule", "rule") + " Shadowrocket Module |\n")
            f.write("| 规则7' |" + self.__subscribeLink("adblockshadowrocketlite.sgmodule", "rule") + " Shadowrocket Module |\n")
            f.write("| 规则8 |" + self.__subscribeLink("adblockqx.conf", "rule") + " QuantumultX |\n")
            f.write("| 规则8' |" + self.__subscribeLink("adblockqxlite.conf", "rule") + " QuantumultX |\n")
            f.write("| 规则9 |" + self.__subscribeLink("adblockmihomo.yaml", "rule") + " Clash Meta(Mihomo) yaml |\n")
            f.write("| 规则9' |" + self.__subscribeLink("adblockmihomolite.yaml", "rule") + " Clash Meta(Mihomo) yaml |\n")
            f.write("| 规则10 |" + self.__subscribeLink("adblockmihomo.mrs", "rule") + " Clash Meta(Mihomo) mrs |\n")
            f.write("| 规则10' |" + self.__subscribeLink("adblockmihomolite.mrs", "rule") + " Clash Meta(Mihomo) mrs |\n")
            f.write("| 规则11 |" + self.__subscribeLink("adblockhosts.txt", "rule") + " Hosts |\n")
            f.write("| 规则11' |" + self.__subscribeLink("adblockhostslite.txt", "rule") + " Hosts |\n")
            f.write("| 规则12 |" + self.__subscribeLink("adblocksingbox.json", "rule") + " sing-box 1.12+ json |\n")
            f.write("| 规则12' |" + self.__subscribeLink("adblocksingboxlite.json", "rule") + " sing-box 1.12+ json |\n")
            f.write("| 规则13 |" + self.__subscribeLink("adblocksingbox.srs", "rule") + " sing-box 1.12+ srs |\n")
            f.write("| 规则13' |" + self.__subscribeLink("adblocksingboxlite.srs", "rule") + " sing-box 1.12+ srs |\n")
            f.write("| 规则14 |" + self.__subscribeLink("adblockloon.list", "rule") + " Loon |\n")
            f.write("| 规则14' |" + self.__subscribeLink("adblockloonlite.list", "rule") + " Loon |\n")
            f.write("| 规则15 |" + self.__subscribeLink("adblocksurge.list", "rule") + " Surge |\n")
            f.write("| 规则15' |" + self.__subscribeLink("adblocksurgelite.list", "rule") + " Surge |\n")
            f.write("| 规则16 |" + self.__subscribeLink("adblockmosdns.txt", "rule") + " MosDNS |\n")
            f.write("| 规则16' |" + self.__subscribeLink("adblockmosdnslite.txt", "rule") + " MosDNS |\n")
            f.write("| 规则17 |" + self.__subscribeLink("adblockv2ray.dat", "rule") + " V2ray、Xray(category-ads-all) |\n")
            f.write("| 规则17' |" + self.__subscribeLink("adblockv2raylite.dat", "rule") + " V2ray、Xray(category-ads-all) |\n")
            f.write("\n")

            f.write("## 上游规则源\n")
            f.write("1. 感谢各位广告过滤规则维护大佬们的辛苦付出。\n")
            f.write("2. 不再引用[anti-AD](https://anti-ad.net/adguard.txt)、[yhosts](https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts.txt)，具体原因见[Mosney/anti-anti-AD](https://github.com/Mosney/anti-anti-AD)。\n")
            f.write("3. 移除[Notracking blocklist](https://raw.githubusercontent.com/notracking/hosts-blocklists/master/adblock/adblock.txt)，原项目[已停止维护](https://github.com/notracking/hosts-blocklists/issues/900)。\n")
            f.write("4. 移除[ADgk](https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt)、[SmartTV Blocklist](https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt)、[1024 hosts](https://raw.githubusercontent.com/Goooler/1024_hosts/master/hosts)、[ad-wars hosts](https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts)规则长时间未更新。\n")
            f.write("5. 不再引用[NEO DEV HOST](https://github.com/neodevpro/neodevhost/blob/master/lite_adblocker)，原因见项目此前的来源审查记录。\n")
            f.write("6. 不再引用[xinggsf rule](https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt)、[1Hosts (Lite)](https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt)、[Hblock](https://hblock.molinero.dev/hosts_adblock.txt)，误杀较多。\n")
            f.write("\n")

            tmp = "| 规则 | 类型 | 原始链接 |"
            for i in range(1, len(self.proxyList)):
                tmp += " 加速链接%d |" % (i)
            tmp += " 更新日期 |\n"
            f.write(tmp)
            tmp = "|" + ":-|" * ( 2 + len(self.proxyList) + 1) + "\n"
            f.write(tmp)
            for rule in self.ruleList:
                f.write("| %s | %s |%s %s |\n" % (rule.name, rule.type, self.__subscribeLink(rule.filename, "source", rule.url), rule.latest))
            f.write("\n")

            f.write("## Star History\n")
            f.write("[![Star History Chart](https://star-history.dera.page/svg?repos=LucentDNS/adblockfilters)](https://star-history.dera.page/#LucentDNS/adblockfilters)\n")
