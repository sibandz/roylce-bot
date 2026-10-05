# Rolyce Pilot

Rolyce Pilot is an invite-only FX practice and charting prototype. The live chart is view-only; current demo prices and signals are synthetic and do not place broker orders.

## Run locally

Requires Node.js 20 or newer.

```powershell
npm install
$env:DATA_DIR = "$PWD\data"
npm start
```

Open `http://localhost:3000`. The SQLite database is stored under `DATA_DIR` (default: `data\rolyce-pilot.sqlite`). Back up and persist this directory when deploying.
The account and login screens require this Node server. Opening `index.html` directly is a local-only preview; it does not create server accounts or sync demo trades.

## Create the administrator login

Run this once on the server (or trusted machine) with the same `DATA_DIR` used by the app:

```powershell
npm run admin -- admin
```

This creates a new `admin` account and generates a random password, shown only once in the terminal. Save it in a password manager. You can replace `admin` with another username. The command refuses to overwrite an existing account. Administrator passwords are stored as scrypt hashes; the login is the same login form used by invited users.

## Issue an invite

Run this command on the server or a trusted admin machine that has access to the same `DATA_DIR`:

```powershell
npm run invite -- "customer name or note"
```

The one-time code is printed once, expires after 30 days, and should be sent privately to the invited user. The server stores only a hash of the code. Users choose a username and password (minimum 12 characters) when redeeming it. Passwords are scrypt-hashed and login sessions use HttpOnly, SameSite cookies.

## Deployment notes

- Deploy as a persistent Node.js service, not as a static-only site or ephemeral serverless function. The SQLite data directory must live on a persistent disk.
- Terminate HTTPS at the host/proxy, set `NODE_ENV=production`, and set `DATA_DIR` to that persistent disk.
- Keep administrator setup, invite generation access, and the SQLite file private; do not publish either.
- The server stores account credentials, sessions, signup-code hashes, and each user's demo account in SQLite. Demo trades remain simulated and are not broker orders.
- The demo account is for practice only. Live mode embeds a TradingView chart and does not provide live signals or execute real trades.
- This prototype is not financial advice and is not ready to manage customer funds or connect to a broker.
