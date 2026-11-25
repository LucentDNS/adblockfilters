import os
from typing import List, Set, Dict

from loguru import logger

from app.base import APPBase


class ShadowrocketModule(APPBase):
    def __init__(
        self,
        blockList: List[str],
        unblockList: List[str],
        filterDict: Dict[str, str],
        filterList: List[str],
        filterList_var: List[str],
        ChinaSet: Set[str],
        fileName: str,
        sourceRule: str,
    ):
        super(ShadowrocketModule, self).__init__(
            blockList,
            unblockList,
            filterDict,
            filterList,
            filterList_var,
            ChinaSet,
            fileName,
            sourceRule,
        )

    def generate(self, isLite: bool = False):
        try:
            if isLite:
                logger.info("generate AdBlock Shadowrocket Module Lite...")
                fileName = self.fileNameLite
                blockList = self.blockListLite
            else:
                logger.info("generate AdBlock Shadowrocket Module...")
                fileName = self.fileName
                blockList = self.blockList

            if os.path.exists(fileName):
                os.remove(fileName)

            with open(fileName, "w", encoding="utf-8", newline="\n") as f:
                title = "LucentDNS AdBlock Shadowrocket Module"
                if isLite:
                    title += " Lite"
                f.write(f"#!name={title}\n")
                f.write(f"#!homepage={self.homepage}\n")
                f.write(f"#!source={self.source}/{os.path.basename(fileName)}\n")
                f.write(f"#!version={self.version}\n")
                f.write(f"#!updated={self.time}\n")
                f.write("\n")
                f.write("[Rule]\n")
                for domain in blockList:
                    f.write(f"DOMAIN-SUFFIX,{domain},REJECT-DROP\n")

            if isLite:
                logger.info("AdBlock Shadowrocket Module Lite: block=%d" % len(blockList))
            else:
                logger.info("AdBlock Shadowrocket Module: block=%d" % len(blockList))
        except Exception as e:
            logger.exception("%s" % e)
            raise
