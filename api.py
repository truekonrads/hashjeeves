from fastapi import FastAPI, Header, Query

app = FastAPI()
from coredis import Redis
import asyncio
import os
from typing import *
import backoff
from dateutil.parser import parse
from datetime import datetime
import pytz
import aiohttp
import ujson as json
import logging
import sys

# if sys.platform == 'win32':
#     loop = asyncio.ProactorEventLoop()
#     asyncio.set_event_loop(loop)
# from pydantic import BaseModel

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
VT_API_KEY = os.getenv("VT_API_KEY", "")
MAX_VT_REQUESTS = int(os.getenv("MAX_VT_REQUESTS", 100))
MAX_TOTAL_REQUESTS = int(os.getenv("MAX_VT_REQUESTS", 500))
LOGGER = logging.getLogger(__name__)


class HashJeevesException(Exception):
    pass


class InvalidAPIKey(HashJeevesException):
    pass


class QuotaExceeded(HashJeevesException):
    pass


import itertools

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
async def vtfetch(hash: str, apikey: str):
    async with app.vt_semaphore:
        url = f"https://www.virustotal.com/api/v3/search"
        headers = {"x-apikey": apikey}
        params = {"query": hash}
        async with aiohttp.ClientSession(raise_for_status=True) as session:
            response = await session.get(url, headers=headers, params=params)

            j = json.loads(await response.text())
            try:
                # stats = j["data"][0]["attributes"]["last_analysis_stats"]
                return j
            except (AttributeError, KeyError, IndexError):
                return None


async def fetch_one(hash, apikey, since, stats_only):
    k = f"hash:{hash}"
    retval = {"hash": hash}
    redis_cache = await app.redis.hgetall(k)
    if redis_cache:
        retval['cache']=True
        ts = datetime.fromtimestamp(int(redis_cache["ts"]), tz=pytz.UTC)
        retval["ts"] = ts
        if since is None or since <= ts:
            # print("REDIS")
            j = json.loads(redis_cache["vtdata"])
            # print(j)
            if stats_only:
                try:
                    stats = j["data"][0]["attributes"]["last_analysis_stats"]
                    retval["stats"] = stats
                except (AttributeError, KeyError, IndexError):
                    pass
            else:
                retval["vtdata"] = j
            return retval
            # return {"hash": hash, "ts": rez["ts"], "stats": stats}

    # fetch from VT:
    ts = int(datetime.now(tz=pytz.UTC).timestamp())
    retval["ts"] = ts
    retval["cache"]=False
    vt_results = await vtfetch(hash, apikey)
    if vt_results:
        await app.redis.hset(k, {"ts": ts, "vtdata": json.dumps(vt_results)})
        if stats_only:
            try:
                stats = vt_results["data"][0]["attributes"]["last_analysis_stats"]
                retval["stats"] = stats

            except (AttributeError, KeyError, IndexError):
                pass

        else:
            retval["vtdata"] = vt_results
        # rez = {"hash": hash, "ts": ts, "stats": stats}
    return retval


async def fetchresults(
    hashes: List[str] | str, apikey: str, since: str = None, stats_only: bool = True
):
    if type(hashes) == str:
        hashes = [hashes]
    results = {}
    if since is not None:
        since = parse(since)
        # Ensure out datetime is timestamp aware
        if since.tzinfo is None:
            since.replace(tzinfo=pytz.UTC)
    results = []
    for chunk in chunked_iterable(hashes, MAX_TOTAL_REQUESTS):
        taskbag = [fetch_one(h, apikey, since, stats_only) for h in chunk]
        results.extend(await asyncio.gather(*taskbag))
    return results
    # results = await gather_with_concurrency(MAX_TOTAL_REQUESTS,*taskbag)

    # for chunk in chunked_iterable(hashes,MAX_TOTAL_REQUESTS):
    #     for h in chunk:

    # return results


@app.post("/api/lookup")
async def lookup(
    hashes: List[str],
    stats_only: bool = Query(
        default=True, description="Return only summary statistics"
    ),
    since: str | None = Query(default=None, description="Not older than timestamp"),
    x_apikey: str = Header(default=VT_API_KEY),
):
    return await fetchresults(hashes, x_apikey, since=since, stats_only=stats_only)


@app.on_event("startup")
def init():
    print("initialising redis")
    app.vt_semaphore = asyncio.Semaphore(MAX_VT_REQUESTS)
    app.redis = Redis.from_url(REDIS_URL, decode_responses=True)
