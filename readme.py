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
        self.proxyList = [""]

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
        rows = [
            ("AdGuard / AdGuard Home DNS", "adblockdns.txt", "DNS 全量"),
            ("AdGuard / AdGuard Home DNS", "adblockdnslite.txt", "DNS Lite"),
            ("AdGuard 浏览器过滤", "adblockfilters.txt", "浏览器补充规则"),
            ("AdGuard 浏览器过滤", "adblockfilterslite.txt", "浏览器补充 Lite"),
            ("InviZible Pro / personalDNSfilter", "adblockdomain.txt", "域名全量"),
            ("InviZible Pro / personalDNSfilter", "adblockdomainlite.txt", "域名 Lite"),
            ("DNSMasq", "adblockdnsmasq.txt", "全量"),
            ("DNSMasq", "adblockdnsmasqlite.txt", "Lite"),
            ("SmartDNS", "adblocksmartdns.conf", "全量"),
            ("SmartDNS", "adblocksmartdnslite.conf", "Lite"),
            ("Shadowrocket", "adblockclash.list", "Clash 规则全量"),
            ("Shadowrocket", "adblockclashlite.list", "Clash 规则 Lite"),
            ("Shadowrocket Module", "adblockshadowrocket.sgmodule", "模块全量"),
            ("Shadowrocket Module", "adblockshadowrocketlite.sgmodule", "模块 Lite"),
            ("Quantumult X", "adblockqx.conf", "全量"),
            ("Quantumult X", "adblockqxlite.conf", "Lite"),
            ("Mihomo", "adblockmihomo.yaml", "YAML 全量"),
            ("Mihomo", "adblockmihomolite.yaml", "YAML Lite"),
            ("Mihomo", "adblockmihomo.mrs", "MRS 全量"),
            ("Mihomo", "adblockmihomolite.mrs", "MRS Lite"),
            ("Hosts", "adblockhosts.txt", "全量"),
            ("Hosts", "adblockhostslite.txt", "Lite"),
            ("sing-box 1.12+", "adblocksingbox.json", "JSON 全量"),
            ("sing-box 1.12+", "adblocksingboxlite.json", "JSON Lite"),
            ("sing-box 1.12+", "adblocksingbox.srs", "SRS 全量"),
            ("sing-box 1.12+", "adblocksingboxlite.srs", "SRS Lite"),
            ("Loon", "adblockloon.list", "全量"),
            ("Loon", "adblockloonlite.list", "Lite"),
            ("Surge", "adblocksurge.list", "全量"),
            ("Surge", "adblocksurgelite.list", "Lite"),
            ("MosDNS", "adblockmosdns.txt", "全量"),
            ("MosDNS", "adblockmosdnslite.txt", "Lite"),
            ("V2Ray / Xray", "adblockv2ray.dat", "DAT 全量"),
            ("V2Ray / Xray", "adblockv2raylite.dat", "DAT Lite"),
        ]
        with open(self.filename, "w", encoding="utf-8", newline="\n") as f:
            f.write("# LucentDNS Adblock Filters\n\n")
            f.write("独立维护的 DNS 与浏览器内容过滤规则。上游来源经过分类、解析、去重和贡献审查；构建包含白名单回归及关键服务检查。\n\n")
            f.write("## DNS 订阅\n\n")
            f.write("| 版本 | 地址 |\n|---|---|\n")
            f.write("| DNS 全量 | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdns.txt |\n")
            f.write("| DNS Lite | https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/adblockdnslite.txt |\n\n")
            f.write("DNS Lite 适用于希望减少规则数量的场景；仅在客户端有需要时再添加浏览器补充规则。\n\n")
            f.write("## 其他客户端订阅\n\n")
            f.write("| 客户端 | 版本 | 订阅地址 |\n|---|---|---|\n")
            for client, filename, variant in rows:
                url = "https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/" + filename
                f.write(f"| {client} | {variant} | {url} |\n")
            f.write("\n")
            f.write("## 上游来源\n\n")
            f.write("以下为本项目实际使用的上游源；本表仅用于来源追溯，不是客户端订阅地址。\n\n")
            f.write("| 来源 | 类型 | 上游地址 | 更新信息 |\n|---|---|---|---|\n")
            for rule in self.ruleList:
                f.write(f"| {rule.name} | {rule.type} | [upstream]({rule.url}) | {rule.latest} |\n")
            f.write("\n")
            f.write("## 维护与反馈\n\n")
            f.write("- 规则产物由 GitHub Actions 自动构建，发布在 dist 分支及 Releases。\n")
            f.write("- 构建审计、来源贡献及与上游基线的差异报告见 audit Release。规则数量差异不等同于质量优劣证明。\n")
            f.write("- 如遇误拦截，请提交反馈并提供被影响的域名、客户端及复现情况；不要直接扩大白名单范围。\n\n")
            f.write("## License\n\nGPL-3.0. 上游规则遵循各自原始许可证及使用条款。\n"
