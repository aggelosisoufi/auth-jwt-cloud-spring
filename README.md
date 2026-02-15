# Spring Cloud JWT (Config Server + JWT Service)

This repository contains a multi-module Spring Boot project:

- `config-server`: Spring Cloud Config Server (native file backend)
- `jwt-service`: JWT auth service using HttpOnly cookies + CSRF + Redis-backed rate limiting

The `jwt-service` loads its runtime configuration from `config-server`.

## Stack

- Java `17` (project `release` target)
- Spring Boot `3.5.7`
- Spring Cloud `2025.0.0`
- Maven `3.9+`
- H2 in-memory database (dev)
- Bucket4j `8.9.0` (distributed rate limiting)
- Redis (rate-limit token storage via Lettuce)

## Prerequisites

- Java 17
- Maven 3.9+
- Redis running on `localhost:6379` (Docker is fine)

## Project Structure

```text
spring-cloud-jwt-main/
├── pom.xml
├── config-server/
│   ├── pom.xml
│   ├── src/main/resources/application.properties
│   └── config-repo/spring-jwt.properties
└── jwt-service/
    ├── pom.xml
    └── src/main/resources/application.properties
```

## Configuration Flow

1. `config-server` starts on `8012`.
2. `jwt-service` starts and uses:
   `spring.config.import=configserver:http://localhost:8012`
3. `config-server` serves values from:
   `config-server/config-repo/spring-jwt.properties`

Important files:

- `config-server/src/main/resources/application.properties`
- `config-server/config-repo/spring-jwt.properties`
- `jwt-service/src/main/resources/application.properties`

## Run Locally (Manual)

Start services in this exact order from the project root.

Terminal 1 (Redis):

```bash
docker run --name rate-limit -p 6379:6379 -d redis
```

Terminal 2:

```bash
mvn -pl config-server spring-boot:run
```

Wait until logs show:

```text
Tomcat started on port 8012
Started ConfigServerApplication
```

Terminal 3:

```bash
mvn -pl jwt-service spring-boot:run
```

Wait until logs show:

```text
Fetching config from server at : http://localhost:8012
Tomcat started on port 8013
Started SpringJwtApplication
```

Alternative (inside module folders):

```bash
cd config-server && mvn spring-boot:run
cd jwt-service && mvn spring-boot:run
```

## Verify Startup

Config server config endpoint:

```bash
curl http://localhost:8012/spring-jwt/default
```

JWT service CSRF endpoint:

```bash
curl -i http://localhost:8013/api/csrf
```

You should receive:

- `200 OK`
- cookie `XSRF-TOKEN=...`
- JSON containing `token`, `headerName`, `parameterName`

## JWT Service Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/csrf` | Issue CSRF token/cookie |
| `POST` | `/api/auth/signup` | Register user |
| `POST` | `/api/auth/signin` | Authenticate and set auth cookies |
| `POST` | `/api/auth/refresh-token` | Refresh access token via refresh cookie |
| `POST` | `/api/auth/logout` | Logout (Spring Security logout endpoint) |
| `GET` | `/api/user` | Protected endpoint (`ROLE_USER`) |

## Rate Limiting (Auth Endpoints)

`jwt-service` includes a `RateLimitFilter` backed by Redis + Bucket4j:

- Applies to:
  - `POST /api/auth/signup`
  - `POST /api/auth/signin`
- Key strategy:
  - signup: `signup:<client-ip>`
  - signin: `signin:<client-ip>`
- On limit exceeded:
  - status `429 Too Many Requests`
  - header `Retry-After: <seconds>`
  - body `Too many requests`

Current bucket rules are defined in:

- `jwt-service/src/main/java/com/angelosisoufi/spring_jwt/spring_jwt/config/RedisConfig.java`

## Request Flow (CSRF + Cookies)

1. Call `GET /api/csrf`.
2. Read token from response body and keep `XSRF-TOKEN` cookie.
3. For `POST` requests, send:
   - header: `X-XSRF-TOKEN: <token>`
   - cookie: `XSRF-TOKEN`
4. Sign in with `POST /api/auth/signin`.
5. Access protected routes using auth cookies.

Example:

```bash
# 1) Get CSRF cookie + token (copy token from JSON response)
curl -i -c cookies.txt http://localhost:8013/api/csrf

# 2) Signup
curl -i -b cookies.txt -c cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: <csrf-token>" \
  -d '{"firstName":"John","lastName":"Doe","email":"john@example.com","password":"StrongPass1!"}' \
  http://localhost:8013/api/auth/signup

# 3) Signin
curl -i -b cookies.txt -c cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: <csrf-token>" \
  -d '{"email":"john@example.com","password":"StrongPass1!"}' \
  http://localhost:8013/api/auth/signin
```

## Error Responses

- Duplicate signup email returns `409 Conflict` (Problem Details response).
- Invalid CSRF token returns `403 Forbidden`.
- Rate-limit exceeded returns `429 Too Many Requests` with `Retry-After`.

## Development Notes

- Auth cookies are currently created with `secure(true)` in `AuthService`.
- On plain HTTP local setups, some clients/browsers may not send `Secure` cookies.
- For local-only testing, either use HTTPS or temporarily switch cookie `secure(false)`.
- H2 console is enabled at `http://localhost:8013/h2-console`.

## Troubleshooting

- `Could not resolve config data` in JWT service:
  - Ensure `config-server` is already running on `8012`.
- Redis connection failures in JWT service:
  - Ensure Redis is running on `localhost:6379`.
- `403 Invalid CSRF token` on signup/signin:
  - First call `GET /api/csrf`.
  - Then send `X-XSRF-TOKEN` header and keep `XSRF-TOKEN` cookie.
- Rate limiting appears inconsistent while testing:
  - Clear Redis state before retesting:
    - `docker exec rate-limit redis-cli FLUSHALL`
- Port already in use:
  - `lsof -nP -iTCP:8012 -sTCP:LISTEN`
  - `lsof -nP -iTCP:8013 -sTCP:LISTEN`
- Running from root with plain `mvn spring-boot:run` will not start modules individually.
  - Use `-pl config-server` and `-pl jwt-service`.

## License

MIT License © 2025 Angelos Isoufi
