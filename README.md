# Rolyce Pilot

Rolyce Pilot is an invite-only FX practice and charting prototype. The live chart is view-only; current demo prices and signals are synthetic and do not place broker orders.

## Run locally

Requires Node.js 22.13 or newer. SQLite is provided by Node.js, so no native addon compiler or separate Python install is needed.

```powershell
npm.cmd install
$env:DATA_DIR = "$PWD\data"
npm.cmd start
```

Leave the terminal running while using the app, and open `http://localhost:3000` in the browser. The SQLite database is stored under `DATA_DIR` (default: `data\rolyce-pilot.sqlite`). Local development uses SQLite; hosted Vercel functions use Supabase. Opening `index.html` directly is a local-only preview; it does not create server accounts or sync demo trades.

## Configure Supabase and Vercel

The frontend deploys as static files while the `api/` directory provides Vercel Functions. Hosted accounts, signup codes, sessions, and demo accounts are stored in Supabase Postgres.

1. In Supabase, open **SQL Editor** and run the migration in [`supabase/migrations/20261108140000_initial_schema.sql`](./supabase/migrations/20261108140000_initial_schema.sql).
2. In your Supabase project's API settings, copy the project URL and the server-side `service_role` key.
3. In the Vercel project's **Settings → Environment Variables**, add `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` for the environments you deploy. The service-role key bypasses row-level security: keep it private, never put it in frontend code, and never commit it.
4. Redeploy the Vercel project. Check `/api/health`; a successful response includes `"database":"supabase"`.

The API routes are `/api/health`, `/api/auth/login`, `/api/auth/signup`, `/api/auth/me`, `/api/auth/logout`, and `/api/demo`. If either variable is missing, the API reports an explicit configuration error. Vercel's function filesystem is not persistent, so hosted data is stored in Supabase rather than local SQLite.

## Create the administrator login

On a trusted machine, set the Supabase variables in the current PowerShell session, then run:

```powershell
$env:SUPABASE_URL = "your Supabase project URL"
$env:SUPABASE_SERVICE_ROLE_KEY = "your private service-role key"
npm.cmd run admin -- admin
```

This creates a new `admin` account and generates a random password, shown only once in the terminal. Save it in a password manager. You can replace `admin` with another username. The command refuses to overwrite an existing account. Administrator passwords are scrypt-hashed; the admin uses the regular login form.

For accounts in the local SQLite development database instead, use `npm.cmd run admin:local -- admin`. Local SQLite users do not automatically exist in Supabase.

## Issue an invite

Run this command on a trusted machine with the same Supabase variables configured for the deployed app:

```powershell
$env:SUPABASE_URL = "your Supabase project URL"
$env:SUPABASE_SERVICE_ROLE_KEY = "your private service-role key"
npm.cmd run invite -- "customer name or note"
```

The one-time code is printed once, expires after 30 days, and should be sent privately to the invited user. Supabase stores only a hash of the code. Users choose a username and password (minimum 12 characters) when redeeming it. Passwords are scrypt-hashed and login sessions use HttpOnly, SameSite cookies.

## Deployment notes

- For Vercel, set `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` for each deployment environment, then redeploy.
- Keep administrator setup, invite generation access, and Supabase service-role credentials private.
- Vercel stores account credentials, sessions, signup-code hashes, and each user's demo account in Supabase. Local development uses SQLite. Demo trades remain simulated and are not broker orders.
- Existing accounts in any previous Firebase/Firestore deployment are not copied automatically; create accounts/invites in Supabase or migrate the data deliberately before switching users over.
- The demo account is for practice only. Live mode embeds a TradingView chart and does not provide live signals or execute real trades.
- This prototype is not financial advice and is not ready to manage customer funds or connect to a broker.
