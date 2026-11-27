import os
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor,as_completed
from typing import List,Dict,Set,Tuple

from loguru import logger
from tld import get_tld

from app import APPBase, AdGuard, AdGuardHome, DNSMasq, Hosts, InviZible, Loon, Mihomo, MosDNS, QuantumultX, Shadowrocket, ShadowrocketModule, SingBox, SmartDNS, Surge, V2ray
from readme import Rule
from resolver import Resolver


def _is_ip_literal(value: str) -> bool:
    """Return True for IP literals, including IPv4-with-port forms."""
    candidate = str(value).strip()
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]
    elif candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _remove_manual_blocks_from_blacklist(blacklist, manual_block_dict):
    """Keep explicitly curated manual blocks even when DNS currently says NXDOMAIN.

    These entries are maintained from threat/ad/tracker evidence, not inferred
    from DNS existence. The manual-block policy therefore overrides only the
    exact-host DNS negative list; normal whitelist handling remains in force.
    This also protects against later reactivation or re-registration of a
    known malicious hostname.
    """
    manual_domains = set()
    for suffix, subdomains in manual_block_dict.items():
        if not suffix:
            continue
        for subdomain in subdomains:
            domain = (f"{subdomain}.{suffix}" if subdomain else suffix).strip().lower()
            if domain and not _is_ip_literal(domain):
                manual_domains.add(domain)
    return {str(domain).strip().lower() for domain in blacklist} - manual_domains


def _build_exact_block_list(block_domains, allow_domains, blacklist, include_domains=None):
    """Build exact-host entries before Full suffix compression, with hierarchical allow rules."""
    allow_domains = {str(domain).strip().lower() for domain in allow_domains if str(domain).strip()}
    blacklist = {str(domain).strip().lower() for domain in blacklist if str(domain).strip()}
    included = None if include_domains is None else {
        str(domain).strip().lower() for domain in include_domains if str(domain).strip()
    }
    candidates = {
        str(domain).strip().lower()
        for domain in block_domains
        if str(domain).strip()
    }
    if included is not None:
        candidates &= included
    result = []
    for domain in candidates:
        if domain in blacklist:
            continue
        labels = domain.split(".")
        # A source allow rule or project whitelist parent protects descendants too.
        if any(".".join(labels[index:]) in allow_domains for index in range(len(labels))):
            continue
        result.append(domain)
    return sorted(result)


def _dns_pattern_matches_domain(rule: str, domain: str) -> bool:
    """Match a whitelist domain against a validated AdGuard DNS hostname rule."""
    if not rule.startswith("||"):
        return False
    body = rule[2:].split("$", 1)[0]
    if not body.endswith("^"):
        return False
    pattern = re.escape(body[:-1]).replace(r"\*", ".*")
    return re.fullmatch(rf"(?:.*\.)?{pattern}", domain, flags=re.IGNORECASE) is not None


def _get_wildcard_white_exceptions(white_domains, wildcard_block_rules):
    """Keep explicitly allowlisted domains reachable when a wildcard block would match."""
    return {
        domain
        for domain in white_domains
        if any(_dns_pattern_matches_domain(rule, domain) for rule in wildcard_block_rules)
    }


def _build_lite_block_list(block_domains, china_domains, allow_domains, blacklist):
    """Build exact-host Lite rules from validated domestic source domains."""
    return _build_exact_block_list(
        block_domains, allow_domains, blacklist, include_domains=china_domains
    )


class Filter(object):
    def __init__(self, ruleList:List[Rule], path:str, outPath:str=None, sourcePath:str=None):
        self.ruleList = ruleList
        self.path = path              # 读取目录：black/china/white（.cache/domain）
        self.outPath = outPath if outPath else path   # 输出目录：生成产物（.cache/out）
        self.sourcePath = sourcePath if sourcePath else path   # 上游源目录：resolver 读取（.cache/source）

    # 获取拦截规则
    def __getFilters(self) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]], Dict[str, str], Dict[str, str], Dict[str, str]]:
        def dictadd(d1:Dict[str,Set], d2:Dict[str,Set]) -> Dict[str,Set]:
            d3 = dict()
            s = set.union(set(d1), set(d2))
            for item in s:
                d3[item] = set.union(d1.get(item, set()), d2.get(item, set()))
            return d3

        thread_pool = ThreadPoolExecutor(max_workers=os.cpu_count() if os.cpu_count() > 4 else 4)
        resolver = Resolver(self.sourcePath)
        # 按来源类型分别解析。DNS/Hosts 来源进入 DNS 域名集合；
        # 浏览器 filter 来源只进入补充过滤规则，禁止把启发式提取的域名
        # 混入 DNS 输出，避免把页面过滤语法误当成可靠的 DNS 拦截依据。
        taskList = []
        for rule in self.ruleList:
            logger.info("resolve %s..."%(rule.name))
            if rule.type == "host":
                taskList.append(("domain", thread_pool.submit(resolver.resolveHost, rule)))
            if rule.type == "dns":
                taskList.append(("domain", thread_pool.submit(resolver.resolveDNS, rule)))
            if rule.type == "dnsfilter":
                taskList.append(("domain", thread_pool.submit(resolver.resolveFilter, rule)))
            if rule.type == "filter":
                taskList.append(("filter", thread_pool.submit(resolver.resolveFilter, rule)))
        # 添加用户维护的补充 DNS 规则
        rule = Rule("myblock", "dns", "", "")
        taskList.append(("domain", thread_pool.submit(resolver.resolveDNS, rule)))

        # 获取解析结果
        blockDict:Dict[str,Set[str]] = dict()
        unblockDict:Dict[str,Set[str]] = dict()
        filterDict:Dict[str,str] = dict()
        dnsPatternBlockMap:Dict[str,str] = dict()
        dnsPatternAllowMap:Dict[str,str] = dict()
        for source_type, future in taskList:
            __blockDict,__unblockDict,__filterDict = future.result()
            if source_type == "domain":
                blockDict = dictadd(blockDict, __blockDict)
                unblockDict = dictadd(unblockDict, __unblockDict)
                for filter_rule, domain in __filterDict.items():
                    pattern = resolver.resolveDNSPattern(filter_rule)
                    if pattern:
                        action, base_domain = pattern
                        if action == "allow":
                            dnsPatternAllowMap[filter_rule] = base_domain
                        else:
                            dnsPatternBlockMap[filter_rule] = base_domain
            else:
                # Browser-only filter sources never enter DNS output.
                for suffix, subdomains in __blockDict.items():
                    for subdomain in subdomains:
                        domain = (subdomain + "." + suffix) if suffix else subdomain
                        filterDict["||%s^" % domain] = domain
                for suffix, subdomains in __unblockDict.items():
                    for subdomain in subdomains:
                        domain = (subdomain + "." + suffix) if suffix else subdomain
                        filterDict["@@||%s^" % domain] = domain
            for filter_rule, domain in __filterDict.items():
                filterDict[filter_rule] = domain

        return blockDict,unblockDict,filterDict,dnsPatternBlockMap,dnsPatternAllowMap

    # 获取黑名单，经测试已无法解析的域名
    def __getBlackList(self, fileName:str) -> Set[str]:
        logger.info("resolve black list...")
        blackSet = set()
        if os.path.exists(fileName):
            with open(fileName, 'r') as f:
                blackList = f.readlines()
                blackSet = set(map(lambda x: x.replace("\n", ""), blackList))
        logger.info("black list: %d"%(len(blackSet)))
        return blackSet

    # 获取白名单，收集的误杀规则
    def __getWhiteList(self, fileName:str) -> Set[str]:
        logger.info("resolve white list...")
        whiteSet = set()
        if os.path.exists(fileName):
            with open(fileName, 'r') as f:
                for line in f.readlines():
                    if not line.startswith("#") and len(line.replace("\n", "")) > 0:
                        whiteSet.add(line.replace("\n", ""))
        logger.info("white list: %d"%(len(whiteSet)))
        return whiteSet

    def __getWhiteDict(self, whiteSet:Set[str]) -> Dict[str,Set[str]]:
        whiteDict = dict()

        for address in whiteSet:
            try:
                # 白名单允许使用纯域名，也兼容 ||domain^$options 形式。
                # 路径/通配符/元素隐藏等浏览器规则不应被误当作 DNS 域名白名单。
                domain = address.strip()
                if domain.startswith("@@||"):
                    domain = domain[4:]
                elif domain.startswith("||"):
                    domain = domain[2:]
                # Modifier-bearing filter exceptions (e.g. $third-party) are
                # exact browser-rule exceptions, not domain-wide DNS whitelists.
                if "$" in domain:
                    continue
                if "^" in domain:
                    domain = domain.split("^", 1)[0]
                if (not domain or domain.endswith(".") or
                        any(char in domain for char in "*/#|?^$")):
                    continue
                res = get_tld(domain, fix_protocol=True, as_object=True)
                fld = res.fld
                subdomain = res.subdomain
                if fld not in whiteDict:
                    whiteDict[fld] = {subdomain}
                else:
                    whiteDict[fld] |= {subdomain}
            except Exception as e:
                logger.warning("white list parse failed: %s (%s)"%(address, e))

        return whiteDict

    # 生成被父级拦截规则覆盖的白名单例外
    def __getWhiteExceptions(self, whiteDict:Dict[str,Set[str]], blockList:List[str]) -> List[str]:
        blocked = set(blockList)
        exceptions = set()
        for fld, subdomains in whiteDict.items():
            for subdomain in subdomains:
                domain = (subdomain + "." + fld) if subdomain else fld
                if any(domain == item or domain.endswith("." + item) for item in blocked):
                    exceptions.add(domain)
        return sorted(exceptions)

    # 获取 China domain 清单，国内域名
    def __getChinaList(self, fileName:str) -> Set[str]:
        logger.info("resolve China list...")
        ChinaSet = set()
        if os.path.exists(fileName):
            with open(fileName, 'r') as f:
                ChinaList = f.readlines()
                ChinaSet = set(map(lambda x: x.replace("\n", ""), ChinaList))
        logger.info("China list: %d"%(len(ChinaSet)))
        return ChinaSet

    # 去重、排序
    def __domainSort(self, domainDict:Dict[str, Set[str]], blackSet:Set[str], whiteDict:Dict[str,Set[str]]) -> Tuple[List[str], Set[str]]:
        def repetition(l): # 短域名已被拦截，则干掉所有长域名。如'a.example'、'b.example'、'example'，则只保留'example'
            s = set(l)
            if len(s) < 2:
                return sorted(s)
            if '' in s:
                return ['']
            out = []
            for item in sorted(s, key=len): # 按从短到长排序
                labels = item.split('.')
                # 任一父后缀已被拦截，则干掉它
                if any('.'.join(labels[k:]) in s for k in range(1, len(labels))):
                    continue
                out.append(item)
            out.sort()
            return out
        def get_domain(fld, subdomain):
            if len(subdomain) > 0:
                domain = ("%s.%s")%(subdomain, fld)
            else:
                domain = ("%s")%(fld)
            return domain

        domanList = []
        domanSet_all = set()
        fldList = list(domainDict.keys())
        fldList.sort() # 排序
        for fld in fldList:
            # DNS domain filters cannot block literal IP addresses. Keep any
            # IP-based browser URL rules in filterList, but exclude IPs here.
            if _is_ip_literal(fld):
                continue
            subdomainList_origin = list(domainDict[fld] - whiteDict.get(fld, set())) # 去除需要保留的白名单域名
            subdomainList = repetition(subdomainList_origin) # 短域名已被拦截，则干掉所有长域名。如'a.example'、'b.example'、'example'，则只保留'example'
            removedList = set(subdomainList_origin) - set(subdomainList) # 被 repetition 干掉的子域名，每个 FLD 只算一次
            for subdomain in subdomainList:
                subdomain_not_black = False
                for _subdomain in removedList:
                    if len(subdomain) > 0:
                        if _subdomain.endswith('.' + subdomain):
                            _domain = get_domain(fld, _subdomain)
                            if _domain not in blackSet:
                                subdomain_not_black = True
                                break
                    else:
                        _domain = get_domain(fld, _subdomain)
                        if _domain not in blackSet:
                            subdomain_not_black = True
                            break

                domain = get_domain(fld, subdomain)
                if domain not in blackSet:
                    domanList.append(domain)
                else:
                    if subdomain_not_black: # 只要子域名有一个未black，仍然保留
                        domanList.append(domain)

            # 全域名保留，用于后续验证连通性
            for subdomain in subdomainList_origin:
                domain = get_domain(fld, subdomain)
                domanSet_all.add(domain)

        return domanList,domanSet_all

    def __filterSort(self, filterDict:Dict[str,str], blockSet:Set[str], unblockSet:Set[str], blackSet:Set[str], whiteSet:Set[str], whiteDict:Dict[str,Set[str]]) -> Tuple[list[str], Set[str]]:
        # Exclude only explicitly reviewed, exact browser rules. This is separate
        # from domain-wide white.txt so path-specific ad rules on the same host
        # remain active.
        exclusion_path = os.path.join(os.path.dirname(__file__), "rules", "filter-exclude.txt")
        filter_exclude_set = set()
        if os.path.isfile(exclusion_path):
            with open(exclusion_path, "r", encoding="utf-8") as stream:
                filter_exclude_set = {
                    line.strip()
                    for line in stream
                    if line.strip() and not line.lstrip().startswith(("!", "#"))
                }
        filterList = list(set(filterDict) - whiteSet - filter_exclude_set)
        whiteDomains = {
            (f"{subdomain}.{fld}" if subdomain else fld)
            for fld, subdomains in whiteDict.items()
            for subdomain in subdomains
        }

        def is_domain_whitelisted(domain):
            labels = domain.split(".")
            return any(".".join(labels[index:]) in whiteDomains
                       for index in range(len(labels)))
        filterList.sort() # 排序
        # 与 adblockdns 去重
        filterList_var = []
        filterList_final = []
        domainSet_all = set()
        for filter in filterList:
            if filter.startswith('#%#var'):
                filterList_var.append(filter)
                continue

            domain = filterDict[filter]
            if domain:
                if is_domain_whitelisted(domain): # 白名单域名及其子域名不进入浏览器拦截规则
                    continue
                if domain in blackSet: # 剔除黑名单
                    continue
                try:
                    res = get_tld(domain, fix_protocol=True, as_object=True)
                    fld = res.fld
                except Exception as e:
                    fld = ''
                if filter.startswith('@@'):
                    if domain in unblockSet or fld in unblockSet: # 剔除 adblockdns 已放行
                        continue
                else:
                    if domain in blockSet or fld in blockSet: # 剔除 adblockdns 已拦截
                        continue
                if not _is_ip_literal(domain):
                    domainSet_all.add(domain)

            filterList_final.append(filter)

        return filterList_var, filterList_final, domainSet_all

    # 生成用于域名连通性检测的全域名清单
    def __generateDomainBackup(self, domainSet, fileName:str):
        logger.info("generate domain backup...")
        if os.path.exists(fileName):
            os.remove(fileName)

        domainList = list(domainSet)
        domainList.sort() # 排序

        with open(fileName, 'a') as f:
            for domain in domainList:
                f.write("%s\n"%(domain))

        logger.info("domain backup: %d"%(len(domainList)))

    def generate(self, sourceRule):
        # 分别记录 DNS/Hosts 来源与浏览器内容过滤来源，避免 DNS 订阅头部误报来源。
        dnsRuleNames = "、".join(rule.name for rule in self.ruleList if rule.type in {"host", "dns", "dnsfilter"})
        # 从上游规则中提取规则
        blockDict,unblockDict,filterDict,dnsPatternBlockMap,dnsPatternAllowMap = self.__getFilters()

        # 提取黑名单、白名单、China domain
        blackSet = self.__getBlackList(self.path + "/black.txt")  # 经测试已无法解析的域名
        # Explicitly curated myblock entries are threat/ad/tracker decisions, not
        # DNS-existence guesses. Do not let NXDOMAIN validation silently erase them.
        manualBlockDict, _, _ = Resolver(self.sourcePath).resolveDNS(
            Rule("myblock", "dns", "", "")
        )
        blackSet = _remove_manual_blocks_from_blacklist(blackSet, manualBlockDict)
        whiteSet = self.__getWhiteList(self.path + "/white.txt")  # 收集的误杀规则
        whiteDict = self.__getWhiteDict(whiteSet)
        ChinaSet = self.__getChinaList(self.path + "/china.txt")  # 国内域名

        # 规则处理：合并、去重、排序、剔除剔除黑名单、剔除白名单
        blockList, blockSet_block = self.__domainSort(blockDict, blackSet, whiteDict)
        unblockList, unblockSet_unblock = self.__domainSort(unblockDict, blackSet, whiteDict)
        whiteDomainSet = {
            (f"{subdomain}.{fld}" if subdomain else fld)
            for fld, subdomains in whiteDict.items()
            for subdomain in subdomains
        }
        # 若白名单子域名被上游父域名或 DNS 通配规则覆盖，必须生成更具体的放行例外。
        whiteExceptions = self.__getWhiteExceptions(whiteDict, blockList)
        wildcardWhiteExceptions = _get_wildcard_white_exceptions(
            whiteDomainSet, dnsPatternBlockMap
        )
        unblockList = sorted(set(unblockList) | set(whiteExceptions) | wildcardWhiteExceptions)
        unblockSet_unblock |= set(whiteExceptions) | wildcardWhiteExceptions
        dnsPatternBlockList = sorted(dnsPatternBlockMap)
        dnsPatternAllowList = sorted(dnsPatternAllowMap)
        dnsPatternBlockListLite = sorted(
            rule for rule, base in dnsPatternBlockMap.items() if base in ChinaSet
        )
        dnsPatternAllowListLite = sorted(
            rule for rule, base in dnsPatternAllowMap.items() if base in ChinaSet
        )
        wildcardWhiteExceptionsLite = sorted(
            _get_wildcard_white_exceptions(whiteDomainSet, dnsPatternBlockListLite)
        )
        logger.info(
            "DNS wildcard patterns: block=%d allow=%d; Lite block=%d allow=%d",
            len(dnsPatternBlockList),
            len(dnsPatternAllowList),
            len(dnsPatternBlockListLite),
            len(dnsPatternAllowListLite),
        )
        filterList_var, filterList, domainSet_filter = self.__filterSort(
            filterDict, set(blockList), set(unblockList), blackSet, whiteSet, whiteDict
        )

        # 生成合并规则 AdGuard, AdGuardHome, DNSMasq, InviZible, SmartDNS等
        generaterList:List[APPBase] = [
            AdGuard           (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblockfilters.txt",           sourceRule),
            AdGuardHome(
                blockList,
                unblockList,
                filterDict,
                filterList,
                filterList_var,
                ChinaSet,
                self.outPath + "/adblockdns.txt",
                dnsRuleNames,
                dnsPatternBlockList=dnsPatternBlockList,
                dnsPatternAllowList=dnsPatternAllowList,
                dnsPatternBlockListLite=dnsPatternBlockListLite,
                dnsPatternAllowListLite=dnsPatternAllowListLite,
                wildcardWhiteExceptionsLite=wildcardWhiteExceptionsLite,
            ),
            DNSMasq           (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblockdnsmasq.txt",           dnsRuleNames),
            Hosts             (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblockhosts.txt",             dnsRuleNames),
            InviZible         (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblockdomain.txt",            dnsRuleNames),
            Loon              (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblockloon.list",             dnsRuleNames),
            Mihomo            (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblockmihomo.yaml",           dnsRuleNames),
            MosDNS            (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblockmosdns.txt",            dnsRuleNames),
            QuantumultX       (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblockqx.conf",               dnsRuleNames),
            Shadowrocket      (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblockclash.list",            dnsRuleNames),
            ShadowrocketModule(blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblockshadowrocket.sgmodule", dnsRuleNames),
            SingBox           (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblocksingbox.json",          dnsRuleNames),
            SmartDNS          (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblocksmartdns.conf",         dnsRuleNames),
            Surge             (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblocksurge.list",            dnsRuleNames),
            V2ray             (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.outPath + "/adblockv2ray.txt",             dnsRuleNames),
        ]
        # Lite uses raw DNS-validated domestic hostnames, not the already-compressed Full list.
        # Each client adapter emits its own exact-host syntax for these entries.
        allowDomainSet = unblockSet_unblock | whiteDomainSet
        liteBlockList = _build_lite_block_list(
            blockSet_block, ChinaSet, allowDomainSet, blackSet
        )
        hostsFullBlockList = _build_exact_block_list(
            blockSet_block, allowDomainSet, blackSet
        )
        for g in generaterList:
            g.blockListLite = liteBlockList
            if isinstance(g, Hosts):
                # Hosts files only match exact hostnames; never feed them a suffix-compressed list.
                g.blockListHosts = hostsFullBlockList
            if isinstance(g, InviZible):
                # DNSCrypt allowlists are a separate native file, not inline blocklist syntax.
                g.unblockList = sorted(allowDomainSet)
            g.generateAll()

        # 生成用于域名连通性检测的全域名清单
        self.__generateDomainBackup(blockSet_block | unblockSet_unblock | domainSet_filter, self.path + "/domain.txt")
