import os
from typing import List, Set, Dict

from loguru import logger

from app.base import APPBase

class Surge(APPBase):
    def __init__(self, blockList:List[str], unblockList:List[str], filterDict:Dict[str,str], filterList:List[str], filterList_var:List[str], ChinaSet:Set[str], fileName:str, sourceRule:str):
        super(Surge, self).__init__(blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, fileName, sourceRule)

    def generate(self, isLite=False):
        try:
            if isLite:
                logger.info("generate adblock Surge Lite...")
                fileName = self.fileNameLite
                blockList = self.blockListLite
            else:
                logger.info("generate adblock Surge...")
                fileName = self.fileName
                blockList = self.blockList

            if os.path.exists(fileName):
                os.remove(fileName)

            # 生成规则文件
            with open(fileName, 'a') as f:
                f.write("#\n")
                if isLite:
                    f.write("#!name=LucentDNS AdBlock Surge Lite\n")
                else:
                    f.write("#!name=LucentDNS AdBlock Surge\n")
                f.write("#!homepage=%s\n"%(self.homepage))
                f.write("#!raw-url=%s/%s\n"%(self.source, os.path.basename(fileName)))
                f.write("#!tag=AdBlock, LucentDNS\n")
                f.write("#!system=iOS, iPadOS\n")
                f.write("#!date=%s\n"%(self.time))
                f.write("#!support=%s\n"%(len(blockList)))
                f.write("#!proxy-select=REJECT\n")
                f.write("#\n")
                for domain in blockList:
                    f.write(f".{domain}\n")

            if isLite:
                logger.info("adblock Surge Lite: block=%d" % (len(blockList)))
            else:
                logger.info("adblock Surge: block=%d" % (len(blockList)))
        except Exception as e:
            logger.exception("%s" % (e))
            raise

