import os
import hashlib
import json

from loguru import logger
from tld.utils import update_tld_names

from readme import ReadMe
from updater import Updater
from filter import Filter
from resolver import configure_logging


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_domain_validation_provenance(ruleList, sourceDir, domainDir):
    """Require the build's DNS sources to match the exact snapshots DNS-validated."""
    provenance_path = os.path.join(domainDir, "domain-input-provenance.json")
    if not os.path.isfile(provenance_path):
        raise RuntimeError("DNS validation provenance is missing; refusing to build without verified inputs")

    with open(provenance_path, "r", encoding="utf-8") as stream:
        provenance = json.load(stream)

    expected_rules = {
        rule.name: rule for rule in ruleList
        if rule.type in ("host", "dns", "dnsfilter")
    }
    source_records = provenance.get("sources")
    if not isinstance(source_records, list):
        raise RuntimeError("DNS validation provenance has no source records")

    records = {item.get("name"): item for item in source_records if isinstance(item, dict)}
    if set(records) != set(expected_rules):
        raise RuntimeError(
            "DNS validation source set changed between validation and build: "
            f"validated={sorted(records)} build={sorted(expected_rules)}"
        )

    for name, rule in expected_rules.items():
        record = records[name]
        if record.get("type") != rule.type or record.get("url") != rule.url:
            raise RuntimeError(f"DNS validation source metadata changed: {name}")
        source_path = os.path.join(sourceDir, rule.filename)
        if not os.path.isfile(source_path):
            raise RuntimeError(f"Validated DNS source snapshot is missing: {name}")
        actual_sha = _sha256_file(source_path)
        if actual_sha != record.get("sha256"):
            raise RuntimeError(
                f"DNS source changed after validation: {name}; "
                f"validated={record.get('sha256')} build={actual_sha}"
            )

    myblock_path = os.path.join(sourceDir, "myblock.txt")
    if not os.path.isfile(myblock_path):
        raise RuntimeError("Validated myblock.txt snapshot is missing")
    actual_myblock_sha = _sha256_file(myblock_path)
    if actual_myblock_sha != provenance.get("myblock_sha256"):
        raise RuntimeError("myblock.txt changed after DNS validation")

    domain_path = os.path.join(domainDir, "domain.txt")
    if not os.path.isfile(domain_path):
        raise RuntimeError("DNS validation domain.txt is missing")
    with open(domain_path, "r", encoding="utf-8") as stream:
        domain_count = sum(1 for line in stream if line.strip())
    if domain_count != provenance.get("unique_validation_domains"):
        raise RuntimeError(
            "DNS validation domain count mismatch: "
            f"provenance={provenance.get('unique_validation_domains')} file={domain_count}"
        )

    expected_domain_sha = provenance.get("domain_file_sha256")
    if expected_domain_sha and _sha256_file(domain_path) != expected_domain_sha:
        raise RuntimeError("domain.txt changed after DNS validation")

    logger.info(
        f"DNS validation provenance verified: {len(expected_rules)} source snapshots, "
        f"{domain_count} candidate domains"
    )
    return True


def update_sources_preserving_validated_dns(ruleList, sourceDir, domainDir):
    """Update browser-only sources; DNS/Hosts sources are immutable validated snapshots."""
    provenance_path = os.path.join(domainDir, "domain-input-provenance.json")
    if not os.path.isfile(provenance_path):
        updater = Updater(ruleList)
        return updater.update(sourceDir)

    with open(provenance_path, "r", encoding="utf-8") as stream:
        provenance = json.load(stream)
    records = {
        item.get("name"): item
        for item in provenance.get("sources", [])
        if isinstance(item, dict)
    }

    dns_types = ("host", "dns", "dnsfilter")
    browser_rules = [rule for rule in ruleList if rule.type not in dns_types]
    dns_metadata = {
        rule.name: records[rule.name]["latest"]
        for rule in ruleList
        if rule.type in dns_types and rule.name in records and "latest" in records[rule.name]
    }

    # These DNS/Hosts files were downloaded, parsed and DNS-validated by the
    # preceding validation workflow. Re-downloading them here is both wasteful
    # and unsafe: a new upstream version has not passed DNS validation yet.
    updated, _ = Updater(browser_rules).update(sourceDir)

    # Keep README dates aligned with the exact DNS snapshots used for this build.
    for rule in ruleList:
        if rule.name in dns_metadata:
            rule.latest = dns_metadata[rule.name]

    # Preserve the complete source list; only browser rules were refreshed.
    return updated, ruleList


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
        '''
        # for test
        testList = []
        for rule in ruleList:
            if rule.type in ['filter']:
                testList.append(rule)
        #    if rule.name in ["AdGuard Mobile Ads filter"]: # "AdRules DNS List", "CJX's Annoyance List", "EasyList China", "EasyList", "EasyPrivacy", "jiekouAD", "xinggsf mv", "xinggsf rule"
        #        testList.append(rule)
        ruleList = testList
        '''
        # 更新上游规则（下载到 .cache/source）
        update, ruleList = update_sources_preserving_validated_dns(
            ruleList, self.sourceDir, self.domainDir
        )

        # Dev builds must use the exact DNS/Hosts snapshots that produced black.txt/china.txt.
        verify_domain_validation_provenance(ruleList, self.sourceDir, self.domainDir)

        # 每次都重新生成：black/china/white/myblock 等输入也会变化。
        # 不能只在上游源变化时构建，否则域名有效性名单更新后产物会长期过期。
        logger.info("source changed: %s; regenerate outputs from current inputs" % update)

        # 生成新规则（读 .cache/domain，输出 .cache/out）
        filter = Filter(ruleList, self.domainDir, self.outDir, self.sourceDir)
        filter.generate(readme.getRulesNames())

        # 生成 readme.md
        readme.setRules(ruleList)
        readme.regenerate()

if __name__ == '__main__':
    '''
    # for test
    logFile = os.getcwd() + "/adblock.log"
    if os.path.exists(logFile):
        os.remove(logFile)
    logger.add(logFile)
    '''
    # 更新 tld
    update_tld_names()

    adBlock = ADBlock()
    adBlock.refresh()
