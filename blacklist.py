import os
import time
import asyncio
import re
import sqlite3
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor,as_completed
from typing import Dict,List,Tuple,Set

import httpx
import IPy
from tld import get_tld
from tld.utils import update_tld_names
from loguru import logger
from dns.asyncresolver import Resolver as DNSResolver
from dns.rdatatype import RdataType as DNSRdataType
from dns.resolver import NXDOMAIN, NoAnswer

def _ip_in_ranges(ip_int:int, starts:List[int], ends:List[int]) -> bool:
    # starts/ends 为已排序且无重叠的 [起始, 结束] 区间，二分查找 O(log N)
    i = bisect_right(starts, ip_int) - 1
    return i >= 0 and ip_int <= ends[i]


def _merge_ip_ranges(pairs):
    """Return sorted, merged inclusive IPv4 ranges for binary-search membership."""
    merged = []
    for start, end in sorted(pairs):
        if start < 0 or end > 0xFFFFFFFF or start > end:
            raise ValueError(f"Invalid IPv4 range: {start}-{end}")
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [item[0] for item in merged], [item[1] for item in merged]


def _blacklist_abnormal(black_count:int, total:int) -> bool:
    # 黑名单占比超过一半即异常（正常比例远低于该阈值）；防止 DNS 故障污染名单。
    return total > 0 and black_count > total // 2

DNS_POSITIVE_REFRESH_SECONDS = 36 * 24 * 60 * 60
DNS_NEGATIVE_RECHECK_SECONDS = 6 * 60 * 60
# Bump when the evidence required to classify a domain as NXDOMAIN changes.
DNS_VALIDATION_PORTS = (5053, 5054, 5055, 5056, 5057, 5058)
DNS_BLOCK_POLICY_VERSION = "5"
DNS_VALIDATION_MAX_CONCURRENCY = 100
# Keep the event loop bounded: never create one asyncio task per input domain.
DNS_VALIDATION_BATCH_SIZE = 500
DNS_UNKNOWN_FAILURE_MIN_SAMPLES = 20
DNS_UNKNOWN_FAILURE_MAX_RATIO = 0.20


def _dns_validation_infrastructure_unhealthy(total: int, unknown: int) -> bool:
    return total >= DNS_UNKNOWN_FAILURE_MIN_SAMPLES and unknown / total > DNS_UNKNOWN_FAILURE_MAX_RATIO


def _iter_batches(items, batch_size: int):
    """Yield bounded slices without scheduling one coroutine per input item."""
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    for offset in range(0, len(items), batch_size):
        yield items[offset:offset + batch_size]



def _needs_dns_validation(ip_list, last_checked, now, is_new=False) -> bool:
    """
    Refresh positive answers every 36 days. Retry empty answers after a short
    cooldown so a second same-day workflow run does not repeat the same DNS
    batch, while the daily schedule still rechecks negative/inconclusive names.
    New domains are always checked immediately.
    """
    age = now - last_checked
    if ip_list:
        return age > DNS_POSITIVE_REFRESH_SECONDS
    return is_new or age > DNS_NEGATIVE_RECHECK_SECONDS


class DomainDatabase(object):
    def __init__(self, dbFile: str):
        self.__table_domain = "T_DOMAIN"
        self.__conn = sqlite3.connect(dbFile)
        self.__execute('PRAGMA synchronous = OFF')
        self.__init_db()

    def close(self):
        self.__execute('VACUUM')
        self.__conn.close()

    def __execute(self, sql:str):
        try:
            return self.__conn.execute(sql)
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            logger.exception(e)
            raise

    def __checkTableExists(self, tableName:str) -> bool: # 检查TABLE是否存在
        try:
            sql = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            tableList = []
            for row in self.__execute(sql):
                tableList.append(row[0])
            if tableName in tableList:
                return True
            return False
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            logger.exception(e)
            return False

    def __updateData(self, sql:str, dataListTuple:list=None): # 批量更新
        c = None
        try:
            c = self.__conn.cursor() #获取游标
            if dataListTuple:
                c.executemany(sql, dataListTuple)
            else:
                c.execute(sql)
            self.__conn.commit()
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            self.__conn.rollback()
            logger.exception(e)
            raise
        finally:
            if c is not None:
                c.close()

    def __init_db(self):
        isExists = self.__checkTableExists(self.__table_domain)
        if not isExists:
            self.__execute('CREATE TABLE %s (  ID INTEGER PRIMARY KEY AUTOINCREMENT,\
                                                    domain TEXT NOT NULL,\
                                                    fld TEXT,\
                                                    subdomain TEXT,\
                                                    ip TEXT,\
                                                    port INTEGER,\
                                                    isBlock INTEGER NOT NULL CHECK (isBlock IN (0, 1)) DEFAULT 0,\
                                                    isChina INTEGER NOT NULL CHECK (isChina IN (0, 1)) DEFAULT 0,\
                                                    timeStamp INTEGER NOT NULL,\
                                                    ipList TEXT,\
                                                    tld TEXT)'%(self.__table_domain))
            self.__execute('CREATE UNIQUE INDEX INDEX_%s_UNIQUE on %s (domain)'%(self.__table_domain, self.__table_domain))
            self.__execute('CREATE INDEX index_%s on %s (isBlock, isChina, timeStamp, tld, fld, domain, ip, port)'%(self.__table_domain, self.__table_domain))
        self.__execute(
            "CREATE TABLE IF NOT EXISTS T_META (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )

    def getMeta(self, key: str):
        row = self.__conn.execute(
            "SELECT value FROM T_META WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else None

    def setMeta(self, key: str, value: str):
        self.__conn.execute(
            "INSERT OR REPLACE INTO T_META (key, value) VALUES (?, ?)",
            (key, value),
        )
        self.__conn.commit()

    def resetBlockedForRevalidation(self) -> int:
        """Clear cached negative decisions so a new policy can re-evaluate them."""
        cursor = self.__conn.execute(
            "UPDATE T_DOMAIN SET isBlock = 0, isChina = 0, timeStamp = 0, ipList = NULL "
            "WHERE isBlock = 1"
        )
        self.__conn.commit()
        return cursor.rowcount

    def getAll(self) -> List[Tuple]:
        sql = "SELECT domain,tld,fld,subdomain,ip,port,isBlock,isChina,timeStamp,ipList FROM %s"%(self.__table_domain)
        return self.__execute(sql)

    def updateALL(self, domainList:List[Tuple]):
        sql = "REPLACE INTO %s (domain, fld, subdomain, ip, port, isBlock, isChina, timeStamp, ipList, tld) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"%(self.__table_domain)
        self.__updateData(sql, domainList)

    def deleteBatch(self, domainList, batch_size=500):
        """
        分批删除域名，避免 too many SQL variables 错误
        """
        total_deleted = 0

        if len(domainList) < 1:
            return total_deleted  # 没有要删除的

        # 开启显式事务（提高性能并保证原子性）
        self.__conn.execute("BEGIN TRANSACTION")
        try:
            for i in range(0, len(domainList), batch_size):
                batch = domainList[i:i+batch_size]
                placeholders = ','.join(['?'] * len(batch))
                sql = f"DELETE FROM {self.__table_domain} WHERE domain IN ({placeholders})"
                cursor = self.__conn.execute(sql, batch)
                total_deleted += cursor.rowcount
            # 提交事务
            self.__conn.commit()
        except Exception as e:
            # 出现异常则回滚并中止构建，不能把未完成的数据库更新当作成功。
            self.__conn.rollback()
            logger.exception(e)
            raise

        return total_deleted

def _apply_dns_block_policy_version(database: DomainDatabase) -> int:
    """Invalidate cached NXDOMAIN decisions whenever the decision policy changes."""
    stored_version = database.getMeta("dns_block_policy_version")
    if stored_version == DNS_BLOCK_POLICY_VERSION:
        return 0
    reset_count = database.resetBlockedForRevalidation()
    database.setMeta("dns_block_policy_version", DNS_BLOCK_POLICY_VERSION)
    return reset_count


class DOMAIN(object):
    def __init__(self, domain:str, tld:str=None, fld:str=None, subdomain:str=None, ip:str=None, port:int=None, isBlock:int=None, isChina:int=None, timeStamp:int=None, ipList:str=None):
        self.domain = domain
        if timeStamp:
            self.__update = False
            self.tld = tld
            self.fld = fld
            self.subdomain = subdomain
            self.ip = ip
            self.port = port
            if self.tld is None and self.fld is not None: # 补充之前缺失的 tld
                self.tld, self.fld, self.subdomain, self.ip, self.port = self.__ip_or_domain(self.domain)
                self.__update = True
            self.__isBlock = isBlock
            self.__isChina = isChina
            self.__timeStamp = timeStamp
            self.__ipList = ipList.split(',') if ipList else []
        else:
            self.__update = True
            self.tld, self.fld, self.subdomain, self.ip, self.port = self.__ip_or_domain(self.domain)
            self.__isBlock = 0
            self.__isChina = 0
            self.__timeStamp = int(time.time())
            self.__ipList = []

    def __ip_or_domain(self, address:str) -> Tuple[str]: # ip, fld, subdomain
        tld, fld, subdomain, ip, port = None, None, None, None, None
        try:
            res = get_tld(address, fix_protocol=True, as_object=True)
            tld = res.tld
            fld = res.fld
            subdomain = res.subdomain if len(res.subdomain) else None
            return tld, fld, subdomain, ip, port
        except Exception as e:
            try:
                if address.find(":") > 0:
                    ip_address = IPy.IP(address[:address.find(":")])
                    if ip_address.iptype() == "PUBLIC":
                        ip = address[ : address.find(":")]
                        port = address[address.find(":")+1 : ]
                else:
                    ip_address = IPy.IP(address)
                    if ip_address.iptype() == "PUBLIC":
                        ip = address
                return tld, fld, subdomain, ip, port
            except Exception as e:
                logger.error('"%s": not domain or ip'%(address))
                return tld, fld, subdomain, ip, port

    def getTimeStamp(self) -> int:
        return self.__timeStamp

    def setBlock(self, isBlock:bool):
        f = 1 if isBlock else 0
        if self.__isBlock != f:
            self.__isBlock = f
            self.__timeStamp = int(time.time())
            self.__update = True

    def getBlock(self) -> bool:
        return True if self.__isBlock else False

    def setChina(self, isChina:bool):
        f = 1 if isChina else 0
        if self.__isChina != f:
            self.__isChina = f
            self.__timeStamp = int(time.time())
            self.__update = True

    def getChina(self) -> bool:
        return True if self.__isChina else False

    def setIPList(self, ipList:List[str]):
        # 此处改为强制更新，解决超过 36 天后重新解析出来的 IP 与原记录一致不更新，导致每次都重新解析的问题。
        self.__ipList = ipList
        self.__timeStamp = int(time.time())
        self.__update = True

    def setCheckedAtNow(self):
        """Remember an inconclusive check without changing the known DNS state."""
        self.__timeStamp = int(time.time())
        self.__update = True

    def getIPList(self) -> List[str]:
        return self.__ipList

    def getUpdate(self) -> bool:
        return self.__update

    def toTuple(self) -> Tuple:
        L = list()
        L.append(self.domain)
        L.append(self.fld)
        L.append(self.subdomain)
        L.append(self.ip)
        L.append(self.port)
        L.append(self.__isBlock)
        L.append(self.__isChina)
        L.append(self.__timeStamp)
        L.append(','.join(map(str, self.__ipList)) if len(self.__ipList) else None)
        L.append(self.tld)
        return tuple(L)


class BlackList(object):
    def __init__(self, path:str):
        self.__databaseFile = os.path.join(path, "domain.db")
        self.__ChinalistFile = os.path.join(path, "china.txt")
        self.__blacklistFile = os.path.join(path, "black.txt")
        self.__domainlistFile = os.path.join(path, "domain.txt")
        self.__directlistFile = os.path.join(path, "rules/direct.txt")
        self.__directlistUrl = "https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/direct.txt"
        self.__IPlistFile = os.path.join(path, "rules/ipv4_china.txt")
        self.__IPlistUrl = "https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/ipv4_china.txt"
        # Cap concurrent DNS checks to reduce upstream resolver rate limiting.
        self.__maxTask = DNS_VALIDATION_MAX_CONCURRENCY

        self.__db = DomainDatabase(self.__databaseFile)

    def close(self):
        self.__db.close()

    def __download(self, fileName, url):
        try:
            fileNameDownload = fileName + ".download"
            if os.path.exists(fileNameDownload):
                os.remove(fileNameDownload)

            with httpx.Client() as client:
                logger.info(f'download %s[%s]' % (os.path.basename(fileName), url))
                response = client.get(url)
                response.raise_for_status()
                contentType = response.headers.get("Content-Type") or ""
                if "text/plain" not in contentType.lower():
                    logger.error(
                        "download %s: unexpected Content-Type[%s]; refusing non-text response"
                        % (fileName, contentType)
                    )
                    return False
                if not response.content or not response.content.strip():
                    logger.error("download %s: empty response; refusing to replace cached data" % fileName)
                    return False
                body_prefix = response.content.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
                if body_prefix.startswith((b"<!doctype html", b"<html")):
                    logger.error("download %s: HTML error page; refusing to replace cached data" % fileName)
                    return False
                with open(fileNameDownload, 'wb') as f:
                    f.write(response.content)

            # Atomic replacement preserves the last known-good cache if the final move fails.
            os.replace(fileNameDownload, fileName)

            return True
        except Exception as e:
            logger.error(f'%s download failed: %s' % (fileName, e))
            return False

    def __getDomainDict(self) -> Dict[str, DOMAIN]:
        logger.info("resolve domain list...")
        domainDict = dict()
        try:
            if os.path.exists(self.__domainlistFile):
                with open(self.__domainlistFile, 'r', encoding='utf-8-sig') as f:
                    for line in f.readlines():
                        # 去掉换行符
                        line = line.replace('\r', '').replace('\n', '').strip().lower().strip(".")
                        # Normalize leading/trailing dots and case before DB lookup.
                        # Adblock suffix notation like ".example.com" is not a DNS qname.
                        if len(line) < 1:
                            continue
                        # 去掉注释
                        if line.startswith('#'):
                            continue
                        domainDict[line] = DOMAIN(line)

            logger.info("domain dict: %d"%(len(domainDict)))
            return domainDict
        except Exception as e:
            logger.error("%s"%(e))
            raise

    def __getDomainSet_CN(self) -> Tuple[Set]:
        logger.info("resolve China domain list...")
        fullSet,domainSet,regexpSet,keywordSet = set(),set(),set(),set()
        try:
            downloaded = self.__download(self.__directlistFile, self.__directlistUrl)
            if not os.path.exists(self.__directlistFile) or os.path.getsize(self.__directlistFile) == 0:
                raise RuntimeError("China direct-domain source is missing or empty")
            if not downloaded:
                logger.warning("Using previously cached China direct-domain source")
            with open(self.__directlistFile, 'r', encoding='utf-8-sig') as f:
                    for line in f.readlines():
                        # 去掉换行符
                        line = line.replace('\r', '').replace('\n', '').strip()
                        # 去掉空行
                        if len(line) < 1:
                            continue
                        # 去掉注释
                        if line.startswith('#'):
                            continue
                        # regexp
                        if line.startswith('regexp:'):
                            regexpSet.add(line[len('regexp:'):])
                            continue
                        # keyword
                        if line.startswith('keyword:'):
                            keywordSet.add(line[len('keyword:'):])
                            continue
                        if line.startswith('full:'):
                            fullSet.add(line[len('full:'):])
                            continue
                        if line.startswith('domain:'):
                            domainSet.add(line[len('domain:'):])
                            continue

            if not (fullSet or domainSet or regexpSet or keywordSet):
                raise RuntimeError("China direct-domain source contains no usable rules")
            logger.info("China domain list: full[%d], domain[%d], regexp[%d], keyword[%d]"%(len(fullSet),len(domainSet),len(regexpSet),len(keywordSet)))
            return fullSet,domainSet,regexpSet,keywordSet
        except Exception as e:
            logger.error("%s"%(e))
            raise

    def __getIPDict_CN(self) -> Tuple[List[int], List[int]]:
        logger.info("resolve China IP list...")
        starts, ends = [], []
        try:
            downloaded = self.__download(self.__IPlistFile, self.__IPlistUrl)
            if not os.path.exists(self.__IPlistFile) or os.path.getsize(self.__IPlistFile) == 0:
                raise RuntimeError("China IPv4 range source is missing or empty")
            if not downloaded:
                logger.warning("Using previously cached China IPv4 range source")
            with open(self.__IPlistFile, 'r', encoding='utf-8-sig') as f:
                    for line in f.readlines():
                        row = line.replace('\r', '').replace("\n", "").split("/")
                        if len(row) != 2:
                            raise ValueError(f"Invalid IPv4 CIDR entry: {line!r}")
                        ip, offset = row[0], int(row[1])
                        if not 0 <= offset <= 32:
                            raise ValueError(f"Invalid IPv4 prefix length: {line!r}")
                        start = IPy.parseAddress(ip)[0]
                        if start > 0xFFFFFFFF:
                            raise ValueError(f"Expected IPv4 address: {line!r}")
                        starts.append(start)
                        ends.append(start + (1 << (32 - offset)) - 1)
            # Normalize order and merge overlapping/adjacent ranges before binary search.
            starts, ends = _merge_ip_ranges(zip(starts, ends))
            if not starts:
                raise RuntimeError("China IPv4 range source contains no usable ranges")
            logger.info("China IP list: %d"%(len(starts)))
            return starts, ends
        except Exception as e:
            logger.error("%s"%(e))
            raise

    async def __resolve(self, dnsresolvers, domain) -> Tuple[List[str], str]:
        """Require all six independent upstreams (3 domestic + 3 global) to agree.

        Each SmartDNS listener maps to one provider. Any positive address keeps
        the domain active. Only six providers returning NXDOMAIN for both A and
        AAAA classify a name as nonexistent. A and AAAA are queried concurrently
        per provider; NODATA, timeout, SERVFAIL, or disagreement are inconclusive.
        """
        if not isinstance(dnsresolvers, (list, tuple)):
            dnsresolvers = [dnsresolvers]
        if len(dnsresolvers) != len(DNS_VALIDATION_PORTS):
            return [], "unknown"

        async def resolve_one_upstream(dnsresolver):
            async def query_type(rdtype):
                try:
                    return "answer", await dnsresolver.resolve(qname=domain, rdtype=rdtype)
                except NXDOMAIN:
                    return "nxdomain", ()
                except NoAnswer:
                    return "no_answer", ()
                except Exception:
                    return "unknown", ()

            results = await asyncio.gather(query_type("A"), query_type("AAAA"))
            ip_list = []
            no_answer_count = 0
            nxdomain_count = 0
            for status, answer in results:
                if status == "nxdomain":
                    nxdomain_count += 1
                elif status == "no_answer":
                    no_answer_count += 1
                elif status == "answer":
                    for item in answer:
                        ip = str(item)
                        if ip not in ("0.0.0.0", "::") and ip not in ip_list:
                            ip_list.append(ip)

            if ip_list:
                return ip_list, "resolved"
            if nxdomain_count == 2:
                return [], "not_found"
            if no_answer_count == 2:
                return [], "no_address"
            return [], "unknown"

        upstream_results = await asyncio.gather(
            *(resolve_one_upstream(resolver) for resolver in dnsresolvers)
        )
        all_ips = []
        for ip_list, _status in upstream_results:
            for ip in ip_list:
                if ip not in all_ips:
                    all_ips.append(ip)
        if all_ips:
            return all_ips, "resolved"
        statuses = [status for _ip_list, status in upstream_results]
        if all(status == "not_found" for status in statuses):
            return [], "not_found"
        if all(status == "no_address" for status in statuses):
            return [], "no_address"
        return [], "unknown"

    async def __pingx(self, dnsresolver:List[DNSResolver], domain:DOMAIN, semaphore):
        async def connect_with_timeout(ip, port, timeout=5):
            writer = None
            try:
                # 用 wait_for 包裹 open_connection，设定总超时
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=timeout
                )
                return True
            except asyncio.TimeoutError:
                logger.error('"%s": connect time out' % (ip))
                return False
            except ConnectionRefusedError:
                logger.error('"%s": connect refused' % (ip))
                return False
            except Exception as e:
                logger.error('"%s": %s' % (ip, e if e else "Connect failed"))
                return False
            finally:
                # 确保资源释放
                if writer:
                    writer.close()
                    await writer.wait_closed()

        async with semaphore: # 限制并发数，超过系统限制后会报错Too many open files
            ipList = []
            status = "unknown"
            if domain.ip:  # IP
                portList = [domain.port] * 3 if domain.port else [80, 443] * 3 # 重试 3 次
                for port in portList:
                    if await connect_with_timeout(domain.ip, port, 5): # 5s 超时
                        ipList.append(domain.ip)
                        status = "resolved"
                        break
            else: # 域名
                count = 2
                while count > 0:
                    ipList, status = await self.__resolve(dnsresolver, domain.domain)
                    if status != "unknown":
                        break
                    count -= 1

            if status == "resolved":
                domain.setIPList(ipList)
                domain.setBlock(False)
            elif status == "not_found":
                domain.setIPList([])
                domain.setBlock(True)
            elif status == "no_address":
                # NOERROR/NODATA only means this RR type has no record.
                # MX, TXT, SRV and other valid records may still exist.
                domain.setIPList([])
                domain.setBlock(False)
            else:
                # Inconclusive DNS/TCP results preserve the previous known state,
                # but receive the same short retry cooldown as other empty answers.
                if domain.ip:
                    logger.warning('"%s": TCP check inconclusive; preserve previous state' % domain.domain)
                # Do not refresh a positive DNS cache timestamp on an inconclusive lookup.
                # Empty/negative cache entries still receive a short retry cooldown.
                if not domain.getIPList():
                    domain.setCheckedAtNow()

            stats = getattr(self, "_BlackList__dns_validation_stats", None)
            if stats is not None and not domain.ip:
                stats["checked"] += 1
                stats[status] += 1

            return domain

    def __generateBlackList(self, blackList):
        logger.info("generate black list...")
        try:
            if os.path.exists(self.__blacklistFile):
                os.remove(self.__blacklistFile)

            with open(self.__blacklistFile, "w", encoding="utf-8", newline="\n") as f:
                for domain in blackList:
                    f.write("%s\n"%(domain))
            logger.info("black domain: %d"%(len(blackList)))
        except Exception as e:
            logger.error("%s"%(e))
            raise

    def __generateChinaList(self, ChinaList):
        logger.info("generate China list...")
        try:
            if os.path.exists(self.__ChinalistFile):
                os.remove(self.__ChinalistFile)

            with open(self.__ChinalistFile, "w", encoding="utf-8", newline="\n") as f:
                for domain in ChinaList:
                    f.write("%s\n"%(domain))
            logger.info("China domain: %d"%(len(ChinaList)))
        except Exception as e:
            logger.error("%s"%(e))
            raise

    def __testDomain(self, domainDict:Dict[str,DOMAIN], nameservers:List[str], port=53):
        logger.info("resolve domain...")

        async def _resolve_all():
            dnsresolvers = []
            if port != DNS_VALIDATION_PORTS[0]:
                raise ValueError("DNS validation must start at the first independent SmartDNS port")
            for resolver_port in DNS_VALIDATION_PORTS:
                dnsresolver = DNSResolver()
                dnsresolver.nameservers = nameservers
                dnsresolver.port = resolver_port
                dnsresolver.timeout = 1.5
                dnsresolver.lifetime = 3.0
                dnsresolvers.append(dnsresolver)
            semaphore = asyncio.Semaphore(self.__maxTask)
            self.__dns_validation_stats = {"checked": 0, "resolved": 0, "not_found": 0, "no_address": 0, "unknown": 0}
            now = int(time.time())
            pending_domains = [
                domain for domain in domainDict.values()
                if _needs_dns_validation(
                    domain.getIPList(), domain.getTimeStamp(), now, domain.getUpdate()
                )
            ]
            total = len(pending_domains)
            completed = 0
            logger.info(
                f"DNS validation queued: {total}; batch_size={DNS_VALIDATION_BATCH_SIZE}; "
                f"concurrency={self.__maxTask}"
            )

            # Process bounded batches rather than creating hundreds of thousands
            # of coroutine/task objects at once. Persist each completed batch to
            # SQLite so an interrupted run does not lose all completed lookups
            # on the runner. Only completed domain records are checkpointed.
            for batch in _iter_batches(pending_domains, DNS_VALIDATION_BATCH_SIZE):
                results = await asyncio.gather(
                    *(self.__pingx(dnsresolvers, domain, semaphore) for domain in batch)
                )
                updates = []
                for domain in results:
                    domainDict[domain.domain] = domain
                    if domain.getUpdate():
                        updates.append(domain.toTuple())
                if updates:
                    self.__db.updateALL(updates)
                completed += len(results)
                logger.info(
                    f"DNS validation progress: {completed}/{total}; "
                    f"checkpointed={len(updates)}"
                )

            resolved = sum(1 for item in domainDict.values() if item.getIPList())
            nxdomain = sum(1 for item in domainDict.values() if item.getBlock())
            unresolved = len(domainDict) - resolved - nxdomain
            stats = self.__dns_validation_stats
            logger.info("DNS validation query summary: " + ", ".join(f"{key}={value}" for key, value in stats.items()))
            logger.info(
                f"DNS validation summary: total={len(domainDict)} resolved={resolved} "
                f"NXDOMAIN={nxdomain} no-address-or-inconclusive={unresolved}"
            )
            if _dns_validation_infrastructure_unhealthy(stats["checked"], stats["unknown"]):
                ratio = stats["unknown"] / stats["checked"]
                raise RuntimeError(
                    "DNS validation infrastructure appears degraded: "
                    f"{stats['unknown']}/{stats['checked']} checked domains were inconclusive ({ratio:.1%}); "
                    "refusing to publish DNS state"
                )
            return domainDict

        return asyncio.run(_resolve_all())

    def __isChinaDomain(self, domain:DOMAIN, fullSet_CN:Set[str], domainSet_CN:Set[str], regexpSet_CN:Set[str], keywordSet_CN:Set[str], IPRanges_CN:Tuple[List[int], List[int]]):
        try:
            # 从域名识别
            if domain.fld:
                # .cn 域名默认为国内
                if domain.fld[-3:] == ".cn":
                    domain.setChina(True)
                    return domain
                # full:
                if domain.domain in fullSet_CN:
                    domain.setChina(True)
                    return domain
                # doamin:
                if domain.fld in domainSet_CN:
                    domain.setChina(True)
                    return domain
                # regexp:
                for regexp in regexpSet_CN:
                    if re.match(regexp, domain.domain):
                        domain.setChina(True)
                        return domain
                # keyword:
                for keyword in keywordSet_CN:
                    if re.match(r".*%s.*"%(keyword), domain.domain):
                        domain.setChina(True)
                        return domain

            # 从 IP 识别
            ip_starts, ip_ends = IPRanges_CN
            ipList = domain.getIPList()
            for ip in ipList:
                if _ip_in_ranges(IPy.parseAddress(ip)[0], ip_starts, ip_ends):
                    domain.setChina(True)
                    return domain

            domain.setChina(False)
            return domain
        except Exception as e:
            logger.error('"%s": not domain'%(domain))
            domain.setChina(False)
            return domain

    def __getDomainDict_db(self, domainDict:Dict[str, DOMAIN]) -> Tuple[Dict[str, DOMAIN], List[str]]:
        logger.info("get domain list from db...")
        deleteList = list()
        try:
            for line in self.__db.getAll():
                if line[0] in domainDict:
                    domainDict[line[0]] = DOMAIN(line[0], line[1], line[2], line[3], line[4], line[5], line[6], line[7], line[8], line[9])
                else:
                    deleteList.append(line[0])
            logger.info("domain dict: %d"%(len(domainDict)))
            return domainDict, deleteList
        except Exception as e:
            logger.error("%s"%(e))
            raise

    def __updateDomainDict_db(self, domainDict:Dict[str, DOMAIN]):
        logger.info("update domain list to db...")
        try:
            L = list()
            for _,v in domainDict.items():
                if v.getUpdate():
                    L.append(v.toTuple())

            if len(L):
                self.__db.updateALL(L)
        except Exception as e:
            logger.error("%s"%(e))
            raise

    def __deleteDomian_db(self, domainList:List[str]):
            logger.info("delete domain from db...")
            try:
                self.__db.deleteBatch(domainList)
            except Exception as e:
                logger.error("%s"%(e))
                raise

    def generate(self):
        try:
            reset_count = _apply_dns_block_policy_version(self.__db)
            if reset_count:
                logger.warning(
                    f"DNS block policy upgraded to {DNS_BLOCK_POLICY_VERSION}; "
                    f"reset {reset_count} cached NXDOMAIN decisions"
                )

            # 获取域名清单 https://raw.githubusercontent.com/217heidai/adblockfilters/refs/heads/main/rules/domain.txt
            domainDict = self.__getDomainDict()
            if len(domainDict) < 1:
                raise RuntimeError("Domain input is missing or contains no usable domains")

            # 获取数据库域名清单
            domainDict, deleteList = self.__getDomainDict_db(domainDict)

            # 获取直连域名清单 https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/direct.txt
            fullSet_CN,domainSet_CN,regexpSet_CN,keywordSet_CN = self.__getDomainSet_CN()

            # 获取国内 IP 清单 https://raw.githubusercontent.com/217heidai/RoutingRules/main/rules/ipv4_china.txt
            IPRanges_CN = self.__getIPDict_CN()

            # 域名解析

            domainDict = self.__testDomain(domainDict, ["127.0.0.1"], 5053) # 通过国内3个、国际3个共6个独立上游验证；全部一致才确认NXDOMAIN

            # 国内域名识别
            thread_pool = ThreadPoolExecutor(max_workers=os.cpu_count() if os.cpu_count() > 4 else 4)
            taskList = []
            for _,v in domainDict.items():
                ipList = v.getIPList()
                if len(ipList):
                    taskList.append(thread_pool.submit(self.__isChinaDomain, v, fullSet_CN, domainSet_CN, regexpSet_CN, keywordSet_CN, IPRanges_CN))
            for future in as_completed(taskList):
                domain:DOMAIN = future.result()
                if domain.getChina():
                    domainDict[domain.domain] = domain

            # 生成 Black 域名列表
            blackList = []
            for k,v in domainDict.items():
                # Only explicit NXDOMAIN is sufficient evidence that a name
                # does not exist. NODATA for A/AAAA can coexist with MX/TXT/SRV
                # records, so it must not create a DNS blacklist entry.
                if v.getBlock():
                    blackList.append(k)
            # SmartDNS 故障时大量域名可能同时返回 NXDOMAIN；异常比例必须阻止发布。
            if _blacklist_abnormal(len(blackList), len(domainDict)):
                raise RuntimeError(
                    "blacklist abnormal: %d/%d domains unresolved" %
                    (len(blackList), len(domainDict))
                )
            blackList.sort()
            # 必须每轮都覆盖文件；空结果也要清空旧名单，防止上轮失效域名残留。
            self.__generateBlackList(blackList)

            # 生成 China 域名列表
            ChinaList = []
            for k,v in domainDict.items():
                if v.getChina() and not v.getBlock():
                    ChinaList.append(k)
            ChinaList.sort()
            # 同样必须覆盖空结果，不能把过期国内域名清单带入下一轮构建。
            self.__generateChinaList(ChinaList)

            # 更新数据库域名清单
            self.__updateDomainDict_db(domainDict)

            # 移除多余域名
            if len(deleteList):
                self.__deleteDomian_db(deleteList)

        except Exception as e:
            logger.error("%s"%(e))
            raise

if __name__ == "__main__":
    path = os.getcwd()

    # 更新 tld
    update_tld_names()

    blackList = BlackList(path)
    blackList.generate()
    blackList.close()
