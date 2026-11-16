# mock-server

In-memory Express mock of the SDK practice API. No database.

## Run

```bash
npm install
npm start
```

Listens on `process.env.PORT` or port 3000, bound to `0.0.0.0`.

`TOKEN_TTL_SECONDS` (optional, default `300`) sets the bearer token lifetime in seconds. It must be a positive integer.

## Deploy on Render

[`render.yaml`](render.yaml) defines a Node web service:

- Build command: `npm install`
- Start command: `npm start`
- Health check: `GET /health`

No database environment variables are required.

## Routes

| Method | Path | Auth |
| --- | --- | --- |
| `GET` | `/health` | No |
| `POST` | `/auth/login` | No |
| `POST` | `/auth/logout` | Bearer token |
| `GET` | `/users/me` | Bearer token |
| `GET` | `/users` | Bearer token |
| `GET` | `/users/:id` | Bearer token |

`POST /auth/login` expects `Content-Type: application/json` and `{ "email", "password" }`. Every seeded user accepts the password `Password123!`.

Protected `GET` requests accept `delayMs` (integer 0–30000) and `fail=500`. `GET /users` accepts `q` to filter name, email, and city.
