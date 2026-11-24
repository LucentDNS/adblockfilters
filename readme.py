import re
import os
from typing import List

from loguru import logger

class Rule(object):
    def __init__(self, name:str, type:str, url:str, latest:str, update:bool=False):
        self.name = name
        self.filename = self.name.replace(' ', '_') + '.txt'
        self.type = type
        self.url = url
        self.latest = latest
        self.update = update

# redme文件操作
class ReadMe(object):
    def __init__(self, filename:str):
        self.filename = filename
        self.repository = os.environ.get("GITHUB_REPOSITORY", "LucentDNS/adblockfilters").strip("/")
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
            link += " [原始链接](https://raw.githubusercontent.com/%s/dist/%s) |" % (self.repository, fileName)

            for i in range(1, len(self.proxyList)):
                proxy = self.proxyList[i]
                link += " [加速链接%d](%s/https://raw.githubusercontent.com/%s/dist/%s) |" % (i, proxy, self.repository, fileName)
        else:
            if url:
                link += " [原始链接](%s) |" % (url)
            else:
                link += " [原始链接](https://github.com/%s/releases/download/%s/%s) |" % (self.repository, tag, fileName)

            for i in range(1, len(self.proxyList)):
                proxy = self.proxyList[i]
                link += " [加速链接%d](%s/https://github.com/%s/releases/download/%s/%s) |" % (i, proxy, self.repository, tag, fileName)

        return link

    def regenerate(self):
        logger.info("regenerate readme...")
        if os.path.exists(self.filename):
            os.remove(self.filename)

        with open(self.filename, 'a') as f:
            f.write("# AdBlock DNS Filters\n")
            f.write("去广告合并规则，每8个小时更新一次。  \n")
            f.write("个人收藏了不少广告过滤规则，但是每次往新设备添加的时候很是头疼，于是写了这个项目，定时自动获取各规则源更新，生成合并规则库。\n")
            f.write("\n")

            f.write("## 重要公告\n")
            f.write("1. 20261120：为解决仓库不断膨胀变大问题，本项目调整了存储结构，后续生成的规则文件将通过 dist 分支和 Releases 分发。请及时更新订阅链接！！！\n")
            f.write("\n")

            f.write("## 说明\n")
            f.write("1. 定时从上游各规则源获取更新，合并去重。\n")
            f.write("2. DNS / Hosts 来源参与 DNS 域名拦截；filter-only 来源只进入浏览器规则，不会把网页过滤列表中的纯域名规则混入 DNS 黑名单。\n")
            f.write("3. DNS 域名经过连通性检查、黑名单与白名单处理；浏览器过滤规则保留原始过滤语法。\n")
            f.write("4. 规则文件通过本仓库 GitHub Releases 与 dist 分支分发；订阅地址指向本仓库。\n")
            f.write("\n")

            f.write("## 订阅链接\n")
            f.write("1. 规则x’为规则x的 Lite 版，仅针对国内域名拦截，体积较小（如添加完整规则报错数量限制，请尝试 Lite 规则）\n")
            f.write("2. AdGuard 等浏览器插件使用规则1 + 规则2；规则2仅包含浏览器专用补充，不参与 DNS 拦截。\n")
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
            f.write("1. 来源分层：dns 用于 DNS 拦截；filter-only 只进入浏览器规则，不污染 DNS 域名黑名单。\n")
            f.write("2. 上游来源按用途、维护状态和增量价值筛选，不以规则数量作为质量标准。\n")
            f.write("3. 历史排除记录：anti-AD、yhosts、Notracking、ADgk、SmartTV Blocklist、1024 hosts、ad-wars、NEO DEV HOST、xinggsf rule、1Hosts Lite、Hblock；排除记录可按新证据重新审查。\n")
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
            f.write("[![Star History Chart](https://star-history.dera.page/svg?repos=%s)](https://star-history.dera.page/#%s)\n" % (self.repository, self.repository))
