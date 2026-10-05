# Rolyce Pilot

Rolyce Pilot is an invite-only FX practice and charting prototype. The live chart is view-only; current demo prices and signals are synthetic and do not place broker orders.

## Run locally

Requires Node.js 22.13 or newer. SQLite is provided by Node.js, so no native addon compiler or separate Python install is needed.

```powershell
npm.cmd install
$env:DATA_DIR = "$PWD\data"
npm.cmd start
```

Leave the terminal running while using the app, and open `http://localhost:3000` in the browser. The SQLite database is stored under `DATA_DIR` (default: `data\rolyce-pilot.sqlite`). This local database is only for local development; Vercel uses Neon Postgres.
The account and login screens require this Node server. Opening `index.html` directly is a local-only preview; it does not create server accounts or sync demo trades.

## Configure Vercel and Neon

The frontend deploys as static files while the `api/` directory provides Vercel Functions. Account storage must use a persistent Neon Postgres database:

1. Connect a Neon Postgres database to the Vercel project (or create one in Neon).
2. Add its connection string as `DATABASE_URL` in Vercel's Production, Preview, and Development environment variables. Never commit the connection string.
3. Redeploy. The first API request creates the required tables and indexes.

The API routes are `/api/health`, `/api/auth/login`, `/api/auth/signup`, `/api/auth/me`, `/api/auth/logout`, and `/api/demo`. Without `DATABASE_URL`, they return an explicit configuration error. Do not use SQLite on Vercel Functions: their file systems are not persistent.

## Create the administrator login

On a trusted machine, set `DATABASE_URL` to the same Neon connection string configured in Vercel, then run:

```powershell
$env:DATABASE_URL = "your Neon connection string"
npm.cmd install
npm.cmd run admin -- admin
```

This creates a new `admin` account and generates a random password, shown only once in the terminal. Save it in a password manager. You can replace `admin` with another username. The command refuses to overwrite an existing account. Administrator passwords are scrypt-hashed; the admin uses the regular login form.

For accounts in the local SQLite development database instead, use `npm.cmd run admin:local -- admin`. Local SQLite users do not automatically exist in Neon.

## Issue an invite

Run this command on a trusted machine with the same Neon `DATABASE_URL` as the deployed app:

```powershell
$env:DATABASE_URL = "your Neon connection string"
npm.cmd run invite -- "customer name or note"
```

The one-time code is printed once, expires after 30 days, and should be sent privately to the invited user. Neon stores only a hash of the code. Users choose a username and password (minimum 12 characters) when redeeming it. Passwords are scrypt-hashed and login sessions use HttpOnly, SameSite cookies.

## Deployment notes

- For Vercel, use the Neon Postgres integration and set `DATABASE_URL` for each deployment environment. Vercel provides HTTPS for the app and API routes.
- Keep administrator setup, invite generation access, and database connection strings private; do not publish them.
- Vercel stores account credentials, sessions, signup-code hashes, and each user's demo account in Neon Postgres. Local development uses SQLite. Demo trades remain simulated and are not broker orders.
- The demo account is for practice only. Live mode embeds a TradingView chart and does not provide live signals or execute real trades.
- This prototype is not financial advice and is not ready to manage customer funds or connect to a broker.
