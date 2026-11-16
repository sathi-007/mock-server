# mock-server

Express mock of the SDK practice API. Seeded users stay in memory. Issued refresh tokens and revocation are stored in `data/tokens.json` so they survive a process restart. No database.

## Run

```bash
npm install
npm start
```

Listens on `process.env.PORT` or port 3000, bound to `0.0.0.0`.

`JWT_SECRET` signs access and refresh tokens. Set it on Render (the blueprint generates one). When it is unset or blank, the server uses the dev-only fallback `dev-only-jwt-secret-change-me`.

Access tokens last 10 minutes. Refresh tokens last 30 minutes.

## Deploy on Render

[`render.yaml`](render.yaml) defines a Node web service:

- Build command: `npm install`
- Start command: `npm start`
- Health check: `GET /health`
- `JWT_SECRET` is optional. Render generates a value when the blueprint creates the service. Locally, an unset secret uses the dev fallback above.

No database environment variables are required.

## Routes

| Method | Path | Auth |
| --- | --- | --- |
| `GET` | `/health` | No |
| `POST` | `/auth/login` | No |
| `POST` | `/auth/refresh` | Refresh token |
| `POST` | `/auth/logout` | Access token |
| `GET` | `/users/me` | Access token |
| `GET` | `/users` | Access token |
| `GET` | `/users/:id` | Access token |

`POST /auth/login` expects `Content-Type: application/json` and `{ "email", "password" }`. Every seeded user accepts the password `Password123!`.

Login returns the previous payload fields plus JWT `AccessToken` (10 minutes) and `RefreshToken` (30 minutes). `accessToken` is the same value as `AccessToken`.

```json
{
  "data": {
    "AccessToken": "<jwt>",
    "RefreshToken": "<jwt>",
    "accessToken": "<same value as AccessToken>",
    "tokenType": "Bearer",
    "expiresIn": 600,
    "user": { "id": "1", "name": "Satish", "email": "satish@example.com", "city": "Tirupati" }
  }
}
```

`POST /auth/refresh` expects `{ "RefreshToken": "<refresh jwt>" }` (`refreshToken` is also accepted). It returns a new `AccessToken` and a rotated `RefreshToken` in the same shape. The previous refresh token stops working. Expired and unknown refresh tokens are rejected.

Protected routes expect `Authorization: Bearer <AccessToken>`. Missing, invalid, and expired access tokens are rejected.

```bash
curl -s -X POST http://localhost:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"satish@example.com","password":"Password123!"}'

curl -s -X POST http://localhost:3000/auth/refresh \
  -H 'content-type: application/json' \
  -d '{"RefreshToken":"<RefreshToken>"}'

curl -s http://localhost:3000/users/me \
  -H 'authorization: Bearer <AccessToken>'
```

Protected `GET` requests accept `delayMs` (integer 0–30000) and `fail=500`. `GET /users` accepts `q` to filter name, email, and city.
