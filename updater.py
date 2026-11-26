import os
import re
import time
import hashlib
import email.utils
import asyncio
from datetime import datetime
from typing import List,Tuple
from urllib.parse import urlsplit

import httpx
from loguru import logger

from readme import Rule

DOWNLOAD_TIMEOUT = httpx.Timeout(90.0, connect=30.0)
METADATA_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
RAW_DOWNLOAD_MAX_ATTEMPTS = 3
RAW_DOWNLOAD_RETRYABLE_STATUSES = {429, 500, 502, 503, 504}


# 上游规则更新
class Updater(object):
    def __init__(self, ruleList:List[Rule]):
        self.ruleList = ruleList
        self.isNeedUpdate = False

    def update(self, path:str) -> Tuple[bool,List[Rule]]:
        async def _update():
            # 限制 GitHub API 查询并发（配合无认证限流）
            self._apiSem = asyncio.Semaphore(4)
            # 并发执行所有下载任务，并直接拿到结果
            tasks = [self.__Download(rule, path) for rule in self.ruleList]
            results = await asyncio.gather(*tasks)

            # 更新规则状态；任一来源下载失败都必须中止，禁止静默生成不完整规则。
            for new in results:
                for rule in self.ruleList:
                    if new.name == rule.name:
                        rule.latest = new.latest
                        rule.update = new.update
                        rule.download_ok = getattr(new, "download_ok", False)
                        if rule.update:
                            self.isNeedUpdate = True   # 只要有一个需要更新就标记
                        break
            failed = [rule.name for rule in self.ruleList if not rule.download_ok]
            if failed:
                raise RuntimeError("Required upstream source download failed: " + ", ".join(failed))
            return self.isNeedUpdate, self.ruleList

        return asyncio.run(_update())

    def __CalcFileSha256(self, filename):
        with open(filename, "rb") as f:
            sha256obj = hashlib.sha256()
            sha256obj.update(f.read())
            hash_value = sha256obj.hexdigest()
            return hash_value

    def __ParseDate(self, value: str):
        """解析 RFC 2822（Last-Modified）或 ISO 8601（GitHub API）日期，返回 aware datetime，失败返回 None"""
        if not value:
            return None
        try:
            return email.utils.parsedate_to_datetime(value)
        except Exception:
            pass
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None

    async def __QueryLastModified(self, url: str) -> str:
        """查询 raw.githubusercontent.com 文件的最后修改日期（返回 YYYY/MM/DD，失败返回空串）
        优先 GitHub API（带 GITHUB_TOKEN），403/失败回退 GitHub commits .atom 网页端点（无 API 限流）"""
        match = re.match(r"https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)", url)
        if not match:
            return ""
        owner, repo, branch, path = match.group(1), match.group(2), match.group(3), match.group(4)

        dt = await self.__QueryApiDate(owner, repo, branch, path)
        if dt:
            return dt
        dt = await self.__QueryAtomDate(owner, repo, branch, path)
        if dt:
            return dt
        return ""

    async def __QueryApiDate(self, owner: str, repo: str, branch: str, path: str) -> str:
        api = "https://api.github.com/repos/%s/%s/commits?path=%s&sha=%s&per_page=1" % (owner, repo, path, branch)
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN", "")
        if token:
            headers["Authorization"] = "token " + token
        try:
            sem = getattr(self, "_apiSem", None)
            if sem is not None:
                await sem.acquire()
            try:
                async with httpx.AsyncClient(timeout=METADATA_TIMEOUT, follow_redirects=True) as client:
                    resp = await client.get(api, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data:
                            dt = self.__ParseDate(data[0]["commit"]["committer"]["date"])
                            if dt:
                                return dt.astimezone().strftime("%Y/%m/%d")
                    elif resp.status_code == 403:
                        logger.warning("query api 403（限流或权限不足）, 回退 atom: %s/%s %s" % (owner, repo, path))
                    else:
                        logger.error(f'query api http %s: %s' % (resp.status_code, api))
            finally:
                if sem is not None:
                    sem.release()
        except Exception as e:
            logger.error(f'query api failed: %s [%s] %s' % (api, type(e).__name__, e))
        return ""

    async def __QueryAtomDate(self, owner: str, repo: str, branch: str, path: str) -> str:
        url = "https://github.com/%s/%s/commits/%s/%s.atom" % (owner, repo, branch, path)
        try:
            async with httpx.AsyncClient(timeout=METADATA_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    m = re.search(r"<updated>([^<]+)</updated>", resp.text)
                    if m:
                        dt = self.__ParseDate(m.group(1))
                        if dt:
                            return dt.astimezone().strftime("%Y/%m/%d")
                else:
                    logger.error(f'query atom http %s: %s' % (resp.status_code, url))
        except Exception as e:
            logger.error(f'query atom failed: %s [%s] %s' % (url, type(e).__name__, e))
        return ""

    async def __GetDownloadResponse(self, client, url: str):
        """仅对 raw.githubusercontent.com 的临时网络错误、429 和 5xx 做有限重试。"""
        is_raw_github = (urlsplit(url).hostname or "").lower() == "raw.githubusercontent.com"
        attempts = RAW_DOWNLOAD_MAX_ATTEMPTS if is_raw_github else 1

        for attempt in range(attempts):
            try:
                response = await client.get(url)
                if (
                    is_raw_github
                    and response.status_code in RAW_DOWNLOAD_RETRYABLE_STATUSES
                    and attempt + 1 < attempts
                ):
                    retry_after = response.headers.get("Retry-After", "")
                    try:
                        delay = min(max(float(retry_after), 0.0), 10.0)
                    except (TypeError, ValueError):
                        delay = float(2 ** attempt)
                    logger.warning(
                        "temporary raw GitHub HTTP %s; retry %s/%s in %ss: %s",
                        response.status_code, attempt + 1, attempts - 1, delay, url
                    )
                    await asyncio.sleep(delay)
                    continue
                response.raise_for_status()
                return response
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if not is_raw_github or attempt + 1 >= attempts:
                    raise
                delay = float(2 ** attempt)
                logger.warning(
                    "temporary raw GitHub network error %s; retry %s/%s in %ss: %s",
                    type(exc).__name__, attempt + 1, attempts - 1, delay, url
                )
                await asyncio.sleep(delay)

        raise RuntimeError(f"raw GitHub download exhausted {attempts} attempts: {url}")

    async def __Download(self, rule:Rule, path:str) -> Rule:
        fileName = path + "/" + rule.filename
        fileName_download = fileName + '.download'
        rule.download_ok = False
        try:
            if os.path.exists(fileName_download):
                os.remove(fileName_download)

            async with httpx.AsyncClient(timeout=DOWNLOAD_TIMEOUT, follow_redirects=True) as client:
                response = await self.__GetDownloadResponse(client, rule.url)
                contentType = response.headers.get("Content-Type") or ""
                if "text/plain" not in contentType:
                    raise Exception("Content-Type[%s] error"%(contentType))
                if not response.content.strip():
                    raise Exception("empty source response")
                if response.text.lstrip().lower().startswith(("<!doctype html", "<html")):
                    raise Exception("HTML response instead of a filter list")
                lastModified = response.headers.get("Last-Modified")
                with open(fileName_download,'wb') as f:
                    f.write(response.content)

            if os.path.exists(fileName):
                sha256Old = self.__CalcFileSha256(fileName)
                sha256New = self.__CalcFileSha256(fileName_download)
                if sha256New != sha256Old:
                    rule.update = True
                os.remove(fileName)
            else:
                rule.update = True

            os.rename(fileName_download, fileName)
            rule.download_ok = os.path.getsize(fileName) > 0
            if not rule.download_ok:
                raise Exception("downloaded source file is empty")

            # 更新日期优先级：上游 Last-Modified > GitHub API(raw源最后 commit) > 内容变化当天
            if lastModified:
                dt = self.__ParseDate(lastModified)
                if dt:
                    rule.latest = dt.astimezone().strftime("%Y/%m/%d")
                else:
                    qdate = await self.__QueryLastModified(rule.url)
                    if qdate:
                        rule.latest = qdate
                    elif rule.update:
                        rule.latest = time.strftime("%Y/%m/%d", time.localtime())
            else:
                qdate = await self.__QueryLastModified(rule.url)
                if qdate:
                    rule.latest = qdate
                elif rule.update:
                    rule.latest = time.strftime("%Y/%m/%d", time.localtime())
            logger.info("%s: latest=%s, update=%s"%(rule.name,rule.latest,rule.update))
            return rule
        except Exception as e:
            logger.error(f'%s download failed: %s' % (rule.name, e))
            return rule
