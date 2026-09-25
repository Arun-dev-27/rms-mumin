# RMS Mumin - demo Business Unit app

A small NestJS app that plays the **RMS Mumin** backend (MUMIN realm) and signs in through Miqaat Core
(`oidc_mfa_auth`) with Authorization Code + PKCE.

- Sign in (AAL1), Sign in + MFA (AAL2), AAL2 with `mfa_max_age=60`
- Realm-wide logout through Core, back-channel logout endpoint (with a "down / 503" switch to watch Core retry)
- Trusted handoff to and from the other demo apps

## Run locally

```bash
cp .env.example .env      # set CLIENT_SECRET (or CLIENT_SECRET_FILE)
npm install
npm run start:dev         # http://localhost:5175
```

## Configuration

| Variable | Meaning |
|---|---|
| `APP_KEY`, `APP_LABEL`, `CLIENT_ID`, `APP_REALM` | Which BU app this is (`rms-mumin-dev`, realm MUMIN locally) |
| `PORT`, `HOST` | Listen address (`HOST=0.0.0.0` when hosted) |
| `BASE_URL` | Public origin; Core must have `<BASE_URL>/auth/callback`, `/logged-out`, `/auth/core/logout` and `/auth/core/handoff` registered |
| `ISSUER` | Core URL |
| `CLIENT_SECRET` / `CLIENT_SECRET_FILE` | client_secret_basic secret from Core registration |
| `PEER_APPS` | Handoff targets: `<client_id>:<label>:<realm>`, comma separated |
| `HANDOFF_PATHS` | Paths accepted from an incoming handoff (`*` = one segment) |

## Deploy (Render)

Build `npm ci --include=dev && npm run build`, start `node dist/main.js`, env vars as above with
`HOST=0.0.0.0` and `NODE_VERSION=22`.
