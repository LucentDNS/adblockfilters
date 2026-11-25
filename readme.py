import re
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

    def getRules(self) -> List[Rule]:
        logger.info("resolve readme...")
        self.ruleList = []
        with open(self.filename, "r") as f:
            for line in f:
                line = line.replace('\r', '').replace('\n', '')
                if line.find('|')==0 and line.rfind('|')==len(line)-1:
                    rule = list(map(lambda x: x.strip(), line[1:-1].split('|')))
                    if len(rule) < 4:
                        continue
                    if rule[2].find('(') > 0 and rule[2].find(')') > 0 and rule[1].find('(') < 0:
                        url = rule[2][rule[2].find('(')+1:rule[2].find(')')]
                        matchObj1 = re.match(r'(http|https)://[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)
                        if matchObj1:
                            self.ruleList.append(Rule(rule[0], rule[1], url, rule[-1]))

        allowed_types = {"filter", "dnsfilter", "dns", "host"}
        seen_names = set()
        seen_filenames = set()
        seen_urls = set()
        for rule in self.ruleList:
            if rule.type not in allowed_types:
                raise ValueError(f"Unsupported upstream source type: {rule.type!r} ({rule.name})")
            if not rule.url.startswith("https://"):
                raise ValueError(f"Upstream source must use HTTPS: {rule.name} -> {rule.url}")
            if rule.name in seen_names:
                raise ValueError(f"Duplicate upstream source name: {rule.name}")
            if rule.filename in seen_filenames:
                raise ValueError(f"Duplicate upstream source filename: {rule.filename}")
            if rule.url in seen_urls:
                raise ValueError(f"Duplicate upstream source URL: {rule.url}")
            seen_names.add(rule.name)
            seen_filenames.add(rule.filename)
            seen_urls.add(rule.url)
        return self.ruleList

    def getRulesNames(self) -> str:
        names = ""

        for rule in self.ruleList:
            names += rule.name + '、'

        return names[:-1]

    def setRules(self, ruleList:List[Rule]):
        self.ruleList = ruleList

    def regenerate(self):
        logger.info("regenerate readme...")
        rows = [
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
            f.write("# AdBlock DNS Filters\n")
            f.write("去广告合并规则，每8个小时更新一次。\n")
            f.write("个人收藏了不少广告过滤规则，但是每次往新设备添加的时候很是头疼，于是写了这个项目，定时自动获取各规则源更新，生成合并规则库。\n\n")
            f.write("本仓库基于 [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 持续维护，保留原作者的规则组织和 Full/Lite 设计，并加强来源校验、双组 DNS 交叉验证与构建回归检查。\n\n")
            f.write("## 说明\n")
            f.write("1. 定时从上游各规则源获取更新，合并去重。\n")
            f.write("2. 使用国内、国际两组相互独立的 DNS 验证组，每组配置 3 个非拦截公共 DNS 上游，分别解析上游规则中的域名。仅当两组均确认 NXDOMAIN 时才剔除；解析超时、无地址、SERVFAIL 或两组结果不一致时保留，避免把临时故障误判为失效域名。\n")
            f.write("3. 本项目以合并、去重和去除经双组 DNS 确认的无效域名为主，不随意改写上游规则语义；项目自维护的 myblock.txt（补充拦截）和 white.txt（放行例外）单独管理，并纳入来源校验与误拦截回归检查。如发现误拦截，请反馈上游；经复现验证后再调整项目白名单。\n")
            f.write("4. 规则文件托管于 GitHub Releases 和 dist 分支，加速通道为 gh-proxy.com / ghfast.top / ghproxy.net，请根据网络情况选择可用订阅地址。\n\n")
            f.write("## 正式订阅（仅列出构建验证通过的产物）\n\n")
            f.write("1. 规则1' 为规则1的 Lite 版，仅针对国内域名拦截，体积较小（如添加完整规则报错数量限制，请尝试 Lite 规则）。\n")
            f.write("2. AdGuard 等浏览器插件使用规则1 + 规则2（规则2为规则1的补充，仅适用于浏览器插件）。\n")
            f.write("3. 原始链接优先；加速链接由第三方提供，可能因地区、运营商或服务状态而波动。手机浏览器（Via、X）订阅失败时请改用原始链接。\n\n")
            f.write("| 规则 | 原始链接 | 加速链接1 | 加速链接2 | 加速链接3 | 适配说明 |\n")
            f.write("|:-|:-|:-|:-|:-|:-|\n")
            def write_subscription(rule_no, filename, adapter):
                url = "https://raw.githubusercontent.com/LucentDNS/adblockfilters/dist/" + filename
                proxy1 = "https://gh-proxy.com/" + url
                proxy2 = "https://ghfast.top/" + url
                proxy3 = "https://ghproxy.net/" + url
                f.write(f"| 规则{rule_no} | [原始链接]({url}) | [加速链接1]({proxy1}) | [加速链接2]({proxy2}) | [加速链接3]({proxy3}) | {adapter} |\n")
            write_subscription("1", "adblockdns.txt", "AdGuard、AdGuard Home 等")
            write_subscription("1'", "adblockdnslite.txt", "AdGuard、AdGuard Home 等")
            for index in range(0, len(rows), 2):
                client, filename, variant = rows[index]
                lite_client, lite_filename, lite_variant = rows[index + 1]
                if client != lite_client or "Lite" not in lite_variant:
                    raise ValueError("Subscription Full/Lite rows must remain paired")
                rule_no = str(index // 2 + 2)
                adapter = "AdGuard 等浏览器插件" if client == "AdGuard 浏览器过滤" else client
                write_subscription(rule_no, filename, adapter)
                write_subscription(rule_no + "'", lite_filename, adapter)
            f.write("\n")
            f.write("## 上游来源\n\n")
            f.write("以下为本项目实际使用的上游源；本表仅用于来源追溯，不是客户端订阅地址。\n\n")
            f.write("| 来源 | 类型 | 上游地址 | 更新信息 |\n|---|---|---|---|\n")
            for rule in self.ruleList:
                f.write(f"| {rule.name} | {rule.type} | [upstream]({rule.url}) | {rule.latest} |\n")
            f.write("\n")
            f.write("## 维护与反馈\n\n")
            f.write("- 规则产物由 GitHub Actions 每 8 小时自动构建；DNS 验证状态每日更新，完成关键服务域名及白名单回归检查后，发布在 dist 分支及 Releases。\n")
            f.write("- 构建审计、来源贡献及与上游基线的差异报告见 audit Release。规则数量差异不等同于质量优劣证明。\n")
            f.write("- 误拦截修正须经复现与回归验证；未经验证不直接扩大白名单范围。\n\n")
            f.write("## License\n\nGPL-3.0. 上游规则遵循各自原始许可证及使用条款。\n")
