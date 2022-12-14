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
MAX_VT_REQUESTS = int(os.getenv("MAX_VT_REQUESTS", 50))
MAX_TOTAL_REQUESTS = int(os.getenv("MAX_VT_REQUESTS", 1000))
LOGGER =  logging.getLogger(__name__)

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
        print("VT")
        url = f"https://www.virustotal.com/api/v3/search"
        headers = {"x-apikey": apikey}
        params = {"query": hash}
        async with aiohttp.ClientSession(raise_for_status=True) as session:
            response = await session.get(url, headers=headers, params=params)

            j = json.loads(await response.text())
            try:
                stats = j["data"][0]["attributes"]["last_analysis_stats"]
                return j
            except (AttributeError, IndexError):
                return None


async def fetch_one(hash, apikey, since):
    k = f"hash:{hash}"
    print(f"K: {k}")
    rez = await app.redis.hgetall(k)
    print(f"REZ: {rez}")
    if rez:
        ts = datetime.fromtimestamp(int(rez["ts"]), tz=pytz.UTC)
        if since is None or since <= ts:
            # print("REDIS")
            return {"hash": hash, "ts": rez["ts"], "stats": json.loads(rez["stats"])}

    # fetch from VT:
    vtrez = await vtfetch(hash, apikey)
    ts = int(datetime.now(tz=pytz.UTC).timestamp())
    rez = {"hash": hash, "ts": ts, "stats": json.dumps(vtrez)}
    await app.redis.hset(k, rez)
    return rez


async def fetchresults(hashes: List[str] | str, apikey: str, since: str = None):
    if type(hashes) == str:
        hashes = [hashes]
    results = {}
    if since is not None:
        since = parse(since)
        # Ensure out datetime is timestamp aware
        if since.tzinfo is None:
            since.replace(tzinfo=pytz.UTC)
    results=[]
    for chunk in chunked_iterable(hashes,MAX_TOTAL_REQUESTS):
        taskbag = [fetch_one(h, apikey, since) for h in chunk]
        results.append(await asyncio.gather(*taskbag))
    return results
    # results = await gather_with_concurrency(MAX_TOTAL_REQUESTS,*taskbag)

    

    # for chunk in chunked_iterable(hashes,MAX_TOTAL_REQUESTS):
    #     for h in chunk:

    # return results


@app.post("/api/lookup")
async def lookup(
    hashes: List[str],
    since: str | None = Query(default=None, description="Not older than timestamp"),
    x_apikey: str = Header(default=VT_API_KEY),
):
    return await fetchresults(hashes, x_apikey, since=since)


@app.on_event("startup")
def init():
    print("initialising redis")
    app.vt_semaphore = asyncio.Semaphore(MAX_VT_REQUESTS)
    app.redis = Redis.from_url(REDIS_URL, decode_responses=True)
