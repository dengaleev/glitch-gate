- [Caddy modules](#caddy-modules)
- [How to check redis keys](#how-to-check-redis-keys)
- [How to check rate limit](#how-to-check-rate-limit)

# Caddy modules

- https://github.com/pberkel/caddy-storage-redis
- https://github.com/mholt/caddy-ratelimit


# How to check redis keys

```bash
redis-cli KEYS '*'
```

# How to check rate limit

```bash
bash check.sh
# Request 1 | URL: localhost:8080 | HTTP Status: 200 | Retry-After:  | Duration: 0.002907s | Time: Sun Jan 26 10:47:52 MSK 2025
# Request 1 | URL: localhost:8081 | HTTP Status: 200 | Retry-After:  | Duration: 0.002073s | Time: Sun Jan 26 10:47:52 MSK 2025
# Request 2 | URL: localhost:8080 | HTTP Status: 200 | Retry-After:  | Duration: 0.003507s | Time: Sun Jan 26 10:47:53 MSK 2025
# Request 2 | URL: localhost:8081 | HTTP Status: 200 | Retry-After:  | Duration: 0.002390s | Time: Sun Jan 26 10:47:53 MSK 2025
# Request 3 | URL: localhost:8080 | HTTP Status: 200 | Retry-After:  | Duration: 0.005664s | Time: Sun Jan 26 10:47:54 MSK 2025
# Request 3 | URL: localhost:8081 | HTTP Status: 200 | Retry-After:  | Duration: 0.002156s | Time: Sun Jan 26 10:47:54 MSK 2025
# Request 4 | URL: localhost:8080 | HTTP Status: 429 | Retry-After: 57 | Duration: 0.002226s | Time: Sun Jan 26 10:47:55 MSK 2025
# Request 4 | URL: localhost:8081 | HTTP Status: 429 | Retry-After: 57 | Duration: 0.001974s | Time: Sun Jan 26 10:47:55 MSK 2025
# Request 5 | URL: localhost:8080 | HTTP Status: 429 | Retry-After: 56 | Duration: 0.001893s | Time: Sun Jan 26 10:47:56 MSK 2025
# Request 5 | URL: localhost:8081 | HTTP Status: 429 | Retry-After: 56 | Duration: 0.001400s | Time: Sun Jan 26 10:47:56 MSK 2025
# Request 6 | URL: localhost:8080 | HTTP Status: 429 | Retry-After: 55 | Duration: 0.005680s | Time: Sun Jan 26 10:47:57 MSK 2025
# Request 6 | URL: localhost:8081 | HTTP Status: 429 | Retry-After: 55 | Duration: 0.002685s | Time: Sun Jan 26 10:47:57 MSK 2025
# Request 7 | URL: localhost:8080 | HTTP Status: 429 | Retry-After: 54 | Duration: 0.005047s | Time: Sun Jan 26 10:47:58 MSK 2025
# Request 7 | URL: localhost:8081 | HTTP Status: 429 | Retry-After: 54 | Duration: 0.002802s | Time: Sun Jan 26 10:47:58 MSK 2025
# Request 8 | URL: localhost:8080 | HTTP Status: 429 | Retry-After: 53 | Duration: 0.005080s | Time: Sun Jan 26 10:47:59 MSK 2025
# Request 8 | URL: localhost:8081 | HTTP Status: 429 | Retry-After: 53 | Duration: 0.001902s | Time: Sun Jan 26 10:47:59 MSK 2025
# Request 9 | URL: localhost:8080 | HTTP Status: 429 | Retry-After: 52 | Duration: 0.004537s | Time: Sun Jan 26 10:48:00 MSK 2025
# Request 9 | URL: localhost:8081 | HTTP Status: 429 | Retry-After: 52 | Duration: 0.002756s | Time: Sun Jan 26 10:48:00 MSK 2025
# Request 10 | URL: localhost:8080 | HTTP Status: 429 | Retry-After: 51 | Duration: 0.004663s | Time: Sun Jan 26 10:48:01 MSK 2025
# Request 10 | URL: localhost:8081 | HTTP Status: 429 | Retry-After: 51 | Duration: 0.002558s | Time: Sun Jan 26 10:48:01 MSK 2025
```
