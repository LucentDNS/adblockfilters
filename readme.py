import json
import re
from pathlib import Path
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

# Upstream source manifest parsing
class ReadMe(object):
    def __init__(self, filename:str):
        self.filename = filename
        self.ruleList:List[Rule] = []

    def getRules(self) -> List[Rule]:
        """Load the maintained source manifest, with README parsing for legacy callers."""
        logger.info("resolve upstream source manifest...")
        self.ruleList = []
        manifest_path = Path(self.filename).resolve().parent / "sources.json"

        if manifest_path.is_file():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(f"Cannot read upstream source manifest: {manifest_path}") from exc
            if not isinstance(manifest, dict) or manifest.get("version") != 1:
                raise ValueError("Unsupported or invalid sources.json manifest version")
            entries = manifest.get("sources")
            if not isinstance(entries, list) or not entries:
                raise ValueError("sources.json must contain a non-empty 'sources' array")
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    raise ValueError(f"sources.json entry {index} must be an object")
                if set(entry) != {"name", "type", "url", "latest"}:
                    raise ValueError(
                        f"sources.json entry {index} must contain exactly name, type, url, latest"
                    )
                if not all(isinstance(entry[key], str) and entry[key].strip()
                           for key in ("name", "type", "url", "latest")):
                    raise ValueError(f"sources.json entry {index} has an empty or non-string field")
                self.ruleList.append(
                    Rule(entry["name"], entry["type"], entry["url"], entry["latest"])
                )
        else:
            # Compatibility path for isolated legacy callers and parser tests.
            # Production builds always use the versioned sources.json manifest.
            with open(self.filename, "r", encoding="utf-8-sig") as stream:
                for line in stream:
                    line = line.replace("\r", "").replace("\n", "")
                    if line.startswith("|") and line.endswith("|"):
                        columns = [item.strip() for item in line[1:-1].split("|")]
                        if len(columns) < 4:
                            continue
                        match = re.search(r"\[upstream\]\((https?://[^)]+)\)", columns[2])
                        if match:
                            self.ruleList.append(
                                Rule(columns[0], columns[1], match.group(1), columns[-1])
                            )

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
