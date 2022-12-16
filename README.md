# hashjeeves
A caching VirusTotal lookup API. 

## But why?

VirusTotal has API limits even in the "unlimited" mode, furthermore it takes time to make those lookups. Which means that if you are enriching a larger data set, then you are spending a lot of time waiting. This microservice does two things:

1. Uses concurrency to look up a lot of hashes quickly
2. Uses a cache to see if a lookup was already done. If it is and cache isn't stale (you tell it how old is acceptable), it will return from cache. This saves time and also API limits when you look up previously analysed data. For example, if you look up all executables from multiple systems.

[API spec](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/truekonrads/hashjeeves/main/openapi.json)

## Running
```uvicorn api:app``` or use docker-compose

## Configuration via environ

| Name            | Default                  | Description                  |
| ----------------|--------------------------|-----------------------------|
| REDIS_URL       |redis://localhost:6379/0  | URL to Redis cache           |
| VT_API_KEY      | (blank)                  | Set default VT key (optional)|
| MAX_VT_REQUESTS | 100                      | Maximum simultaneous VT requests |
| MAX_TOTAL_REQUESTS | 500                   | Maximum concurrency limit (set to about 5x of VT ) |

## How to invoke it?
```python 
import requests

with open(r"hashes.txt","r") as f:
    hashes=[x.strip() for x in f]

stats_only="true" # Only return detection stats
                  # Set to "false" to get back full VT response
                  
requests.post(f"http://localhost:8000/api/lookup?stats_only={stats_only}",
                    json=hashes, 
                    headers= {'x-apikey': 'my-vt-api-key'})
```
