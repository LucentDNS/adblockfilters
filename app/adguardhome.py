import os
from typing import List, Set, Dict

from loguru import logger

from app.base import APPBase

class AdGuardHome(APPBase):
    def __init__(
        self,
        blockList:List[str],
        unblockList:List[str],
        filterDict:Dict[str,str],
        filterList:List[str],
        filterList_var:List[str],
        ChinaSet:Set[str],
        fileName:str,
        sourceRule:str,
        dnsPatternBlockList=None,
        dnsPatternAllowList=None,
        dnsPatternBlockListLite=None,
        dnsPatternAllowListLite=None,
        wildcardWhiteExceptionsLite=None,
    ):
        super(AdGuardHome, self).__init__(
            blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, fileName, sourceRule
        )
        self.dnsPatternBlockList = sorted(set(dnsPatternBlockList or []))
        self.dnsPatternAllowList = sorted(set(dnsPatternAllowList or []))
        self.dnsPatternBlockListLite = sorted(set(dnsPatternBlockListLite or []))
        self.dnsPatternAllowListLite = sorted(set(dnsPatternAllowListLite or []))
        self.wildcardWhiteExceptionsLite = sorted(set(wildcardWhiteExceptionsLite or []))

    def generate(self, isLite=False):
        try:
            if isLite:
                logger.info("generate adblock AdGuardHome Lite...")
                fileName = self.fileNameLite
                blockList = self.blockListLite
                unblockList = sorted(
                    set(self.unblockListLite) | set(self.wildcardWhiteExceptionsLite)
                )
                patternBlockList = self.dnsPatternBlockListLite
                patternAllowList = self.dnsPatternAllowListLite
            else:
                logger.info("generate adblock AdGuardHome...")
                fileName = self.fileName
                blockList = self.blockList
                unblockList = self.unblockList
                patternBlockList = self.dnsPatternBlockList
                patternAllowList = self.dnsPatternAllowList
            
            if os.path.exists(fileName):
                os.remove(fileName)
            
            # Keep the subscription expiry aligned with blacklist.yml's daily 16:43 Beijing-time schedule.
            # 生成规则文件
            with open(fileName, 'a') as f:
                f.write("!\n")
                if isLite:
                    f.write("! Title: AdBlock DNS Lite\n")
                    f.write("! Description: 适用于 AdGuard、AdGuardHome 的去广告合并规则，每日自动更新一次。规则源：%s。Lite 版按国内 DNS 识别结果筛选；AdGuard DNS 规则按标准语法匹配该域名及其子域名。\n"%(self.sourceRule))
                    f.write("! Expires: 1 day\n")
                else:
                    f.write("! Title: AdBlock DNS\n")
                    f.write("! Description: 适用于 AdGuard、AdGuardHome 的去广告合并规则，每日自动更新一次。规则源：%s。\n"%(self.sourceRule))
                    f.write("! Expires: 1 day\n")
                f.write("! Homepage: %s\n"%(self.homepage))
                f.write("! Source: %s/%s\n"%(self.source, os.path.basename(fileName)))
                f.write("! Version: %s\n"%(self.version))
                f.write("! Last modified: %s\n"%(self.time))
                f.write("! Blocked domains: %s\n"%(len(blockList)))
                f.write("! Allowed domains: %s\n"%(len(unblockList)))
                f.write("! Wildcard block rules: %s\n"%(len(patternBlockList)))
                f.write("! Wildcard allow rules: %s\n"%(len(patternAllowList)))
                f.write("!\n")
                for domain in blockList:
                    f.write("||%s^\n" % (domain))
                for rule in patternBlockList:
                    f.write("%s\n" % (rule))
                for domain in unblockList:
                    f.write("@@||%s^\n" % (domain))
                for rule in patternAllowList:
                    f.write("%s\n" % (rule))
            
            logger.info(
                f"adblock AdGuardHome{' Lite' if isLite else ''}: "
                f"block={len(blockList)}, allow={len(unblockList)}, "
                f"wildcard_block={len(patternBlockList)}, wildcard_allow={len(patternAllowList)}"
            )
        except Exception as e:
            logger.exception("%s"%(e))
            raise