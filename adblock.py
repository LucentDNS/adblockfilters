import os
import hashlib
from loguru import logger
from tld.utils import update_tld_names

from readme import ReadMe
from updater import Updater
from filter import Filter
from resolver import configure_logging
from scripts.generate_china_list import generate_china_list


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ADBlock(object):
    def __init__(self):
        self.pwd = os.getcwd()
        self.cacheDir = os.path.join(self.pwd, '.cache')
        self.sourceDir = os.path.join(self.cacheDir, 'source')   # 上游规则源下载目录
        self.outDir    = os.path.join(self.cacheDir, 'out')       # 生成产物目录
        self.domainDir = os.path.join(self.cacheDir, 'domain')    # black/china/white/myblock/domain.txt

    def refresh(self):
        for d in (self.sourceDir, self.outDir, self.domainDir):
            os.makedirs(d, exist_ok=True)

        readme = ReadMe(self.pwd + '/README.md')
        ruleList = readme.getRules()
        # Refresh every configured upstream source directly.
        # DNS existence checks are independent diagnostics and never gate source updates.
        update, ruleList = Updater(ruleList).update(self.sourceDir)

        # 每次都重新生成：black/china/white/myblock 等输入也会变化。
        # 不能只在上游源变化时构建，否则域名有效性名单更新后产物会长期过期。
        logger.info("source changed: %s; regenerate outputs from current inputs" % update)

        # 生成新规则（读 .cache/domain，输出 .cache/out）
        filter = Filter(ruleList, self.domainDir, self.outDir, self.sourceDir)
        filter.generate(readme.getRulesNames())

        # The first pass writes the current normalized DNS/Hosts domain input.
        # Build Lite's domestic scope from .cn and explicit routing-domain rules,
        # optionally retaining previous successful DNS-positive classifications.
        # This avoids making every daily production build wait for bulk DNS probes.
        china_provenance = generate_china_list(self.domainDir)
        logger.info(
            "Lite domestic classification: %s domains from conservative direct rules",
            china_provenance["china_classified_domain_count"],
        )
        filter.generate(readme.getRulesNames())


if __name__ == '__main__':
    configure_logging()
    # 更新 tld
    update_tld_names()

    adBlock = ADBlock()
    adBlock.refresh()
