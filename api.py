from fastapi.responses import Response
from fastapi.logger import logger
import itertools
import uvicorn
import logging
import ujson as json
import aiohttp
import pytz
from datetime import datetime
from dateutil.parser import parse
import backoff
from typing import *
import os
import asyncio
from coredis import Redis
from fastapi import FastAPI, Header, Query, HTTPException

app = FastAPI()
logger = logging.getLogger('uvicorn.debug')


REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
VT_API_KEY = os.getenv("VT_API_KEY", "")
MAX_VT_REQUESTS = int(os.getenv("MAX_VT_REQUESTS", 100))
MAX_TOTAL_REQUESTS = int(os.getenv("MAX_TOTAL_REQUESTS", 500))


# https://alexwlchan.net/2018/12/iterating-in-fixed-size-chunks/
def chunked_iterable(iterable, size):
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, size))
        if not chunk:
            break
        yield chunk


async def gather_with_concurrency(n, *coros):
    semaphore = asyncio.Semaphore(n)

    async def sem_coro(coro):
        async with semaphore:
            return await coro

    return await asyncio.gather(*(sem_coro(c) for c in coros))


def vt_exc_check(e: aiohttp.ClientResponseError):
    # https://developers.virustotal.com/reference/errors
    if e.message in ("TransientError", "DeadlineExceededError"):
        return False
    else:
        return True


@backoff.on_exception(backoff.expo, (aiohttp.ClientResponseError), giveup=vt_exc_check)
async def vtfetch(url: str, apikey: str, params: dict):
    # print(f"vtf: {hash}")
    # LOGGER.debug(f"VT fetch {hash}")
    async with app.vt_semaphore:
        headers = {"x-apikey": apikey}
        async with aiohttp.ClientSession(raise_for_status=False) as session:
            response = await session.get(url, headers=headers, params=params)
            # 404 means ismply that hash is not found
            if response.status in (200, 404):
                j = json.loads(await response.text())
                return j
            else:
                response.raise_for_status()


async def vtfetch_file(hash: str, apikey: str):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    params = {}
    return await vtfetch(url, apikey, params)


async def vtfetch_file_comments(vt_id: str, apikey: str):
    url = f"https://www.virustotal.com/api/v3/files/{vt_id}/comments"
    # 40 is the maximum than can be retrieved in one go
    params = {"limit": 40}
    # TODO: implement cursor to fetch > 40 comments
    return await vtfetch(url, apikey, params)


async def fetch_redis_cache(key: str, since: int):
    """
    Retrieves cached data from Redis if available and not expired.
    Args:
        key (str): The key to retrieve data from Redis.
        since (int, optional): The timestamp to check if the cached data is expired.

    Returns:
        dict: The cached data if available and not expired, otherwise None.
    """
    redis_cache = await app.redis.hgetall(key)
    if redis_cache:
        ts = datetime.fromtimestamp(int(redis_cache["ts"]), tz=pytz.UTC)
        if since is None or since <= ts:
            return redis_cache
    return None


async def fetch_one(hash, apikey: str, since: int, stats_only: bool, comments: bool):
    # Lowercase the hash for consistency
    k = f"hash:{hash.lower()}"
    retval = {"hash": hash}
    redis_cache = await fetch_redis_cache(k, since)

    if redis_cache:

        retval['cache'] = True
        ts = datetime.fromtimestamp(int(redis_cache["ts"]), tz=pytz.UTC)
        retval["ts"] = ts.isoformat()
        vt_data = json.loads(redis_cache["vtdata"])
    else:
        # fetch from VT:
        ts = int(datetime.now(tz=pytz.UTC).timestamp())
        retval["ts"] = ts.isoformat()
        retval["cache"] = False
        vt_results = await vtfetch_file(hash, apikey)
        if vt_results:
            await app.redis.hset(k, {"ts": ts, "vtdata": json.dumps(vt_results)})
            vt_data = vt_results
        else:
            raise HTTPException(500, "No VT data was returned")

    if stats_only:
        try:
            stats = vt_data["data"]["attributes"]["last_analysis_stats"]
            retval["stats"] = stats

        except (AttributeError, KeyError, IndexError):
            pass
    else:
        retval["vtdata"] = vt_data
    # if 'error' in vt_data:
    if comments and not ('error' in vt_data):
        vt_id = vt_data['data']['id']
        comment_key = f"comment:{vt_id}"
        redis_cache = await fetch_redis_cache(comment_key, since)
        if redis_cache:
            retval['comment_cache'] = True
            ts = datetime.fromtimestamp(int(redis_cache["ts"]), tz=pytz.UTC)
            retval["comment_ts"] = ts
            comment_data = json.loads(redis_cache["vtdata"])
        else:
            # fetch from VT:
            ts = int(datetime.now(tz=pytz.UTC).timestamp())
            retval["ts"] = ts
            retval["comment_cache"] = False
            comment_data = await vtfetch_file_comments(vt_id, apikey)
            if comment_data:
                await app.redis.hset(k, {"ts": ts, "comment": json.dumps(comment_data)})
            else:
                raise HTTPException(500, "No VT comment data was returned")
        retval['comment_data'] = comment_data

    return retval


async def fetchresults(
    hashes: List[str] | str, apikey: str, since: str = None, stats_only: bool = True,
    comments: bool = False
):
    if type(hashes) == str:
        hashes = [hashes]
    results = {}
    if since is not None:
        since = parse(since)
        # Ensure out datetime is timestamp aware
        if since.tzinfo is None:
            since.replace(tzinfo=pytz.UTC)

    async def call_after(f, after_f, *args, **kwargs):
        try:
            return await f(*args, **kwargs)
        finally:
            after_f()

    results = []
    taskbag = []
    for h in hashes:
        await app.task_semaphore.acquire()
        task = asyncio.create_task(call_after(
            fetch_one, app.task_semaphore.release, h, apikey, since, stats_only, comments))
        taskbag.append(task)
    results.extend(await asyncio.gather(*taskbag))

    return results


@app.post("/api/lookup")
async def lookup(
    hashes: List[str],
    stats_only: bool = Query(
        default=True, description="Return only summary statistics"
    ),
    comments: bool = Query(
        default=False, description="Fetch and return comments"
    ),
    since: str | None = Query(
        default=None, description="Not older than timestamp"),
    x_apikey: str = Header(default=VT_API_KEY),
):
    try:
        if x_apikey is None or x_apikey == "":
            raise HTTPException(500, detail=f"x-apikey is invalid: {x_apikey}")

        results = await fetchresults(hashes, x_apikey, since=since, stats_only=stats_only, comments=comments)

        # This works around an odd bug where indent=None is not respected in json.dumps
        ret = json.dumps(results,
                         separators=(",", ":"),
                         ensure_ascii=False,
                         allow_nan=False,
                         indent=0)
        return Response(ret, media_type="application/json")
    except Exception as e:
        logger.error(f"Error while looking up hashes: {e}")
        raise HTTPException(500, detail=str(e))


@app.on_event("startup")
async def init():
    logger.debug("initialising redis")
    app.vt_semaphore = asyncio.Semaphore(MAX_VT_REQUESTS)
    app.task_semaphore = asyncio.Semaphore(MAX_TOTAL_REQUESTS)
    app.redis = Redis.from_url(REDIS_URL, decode_responses=True)
    logger.info(await asyncio.wait_for(app.redis.ping("REDIS READY"), 2))

if __name__ == "__main__":

    logger = logging.getLogger('uvicorn.debug')
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="debug")
