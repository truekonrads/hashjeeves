# hashjeeves
A caching VirusTotal lookup API

[API spec](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/truekonrads/hashjeeves/main/openapi.json)

## Running
```uvicorn api:app```

## Configuration via environ

| Name            | Default                  | Description                  |
| ----------------|--------------------------|-----------------------------|
| REDIS_URL       |redis://localhost:6379/0  | URL to Redis cache           |
| VT_API_KEY      | (blank)                  | Set default VT key (optional)|
| MAX_VT_REQUESTS | 100                      | Maximum simultaneous VT requests |
| MAX_TOTAL_REQUESTS | 500                   | Maximum concurrency limit (set to about 5x of VT ) |
