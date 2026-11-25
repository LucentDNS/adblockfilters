import os
from typing import List, Set, Dict

from loguru import logger

from app.base import APPBase

class SingBox(APPBase):
    def __init__(self, blockList:List[str], unblockList:List[str], filterDict:Dict[str,str], filterList:List[str], filterList_var:List[str], ChinaSet:Set[str], fileName:str, sourceRule:str):
        super(SingBox, self).__init__(blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, fileName, sourceRule)

    def generate(self, isLite=False):
        try:
            if isLite:
                logger.info("generate adblock sing-box Lite...")
                fileName = self.fileNameLite
                blockList = self.blockListLite
            else:
                logger.info("generate adblock sing-box...")
                fileName = self.fileName
                blockList = self.blockList
            
            tmpList = [x for x in blockList if self.isDomain(x)]
            blockList = tmpList

            if os.path.exists(fileName):
                os.remove(fileName)
            
            # 生成规则文件
            with open(fileName, 'a') as f:
                f.write('{\n')
                f.write('  "version": 3,\n')
                f.write('  "rules": [\n')
                f.write('    {\n')
                match_key = "domain" if isLite else "domain_suffix"
                f.write('      "%s": [\n' % match_key)
                for i, domain in enumerate(blockList):
                    comma = "," if i < len(blockList) - 1 else ""
                    f.write('        "%s"%s\n' % (domain, comma))
                f.write('      ]\n')
                f.write('    }\n')
                f.write('  ]\n')
                f.write('}\n')

            if isLite:
                logger.info("adblock sing-box Lite: block=%d"%(len(blockList)))
            else:
                logger.info("adblock sing-box: block=%d"%(len(blockList)))
        except Exception as e:
            logger.exception("%s"%(e))
            raise
