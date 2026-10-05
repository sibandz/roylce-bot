# Rolyce Pilot

Rolyce Pilot is an invite-only FX practice and charting prototype. The live chart is view-only; current demo prices and signals are synthetic and do not place broker orders.

## Run locally

Requires Node.js 22.13 or newer. SQLite is provided by Node.js, so no native addon compiler or separate Python install is needed.

```powershell
npm.cmd install
$env:DATA_DIR = "$PWD\data"
npm.cmd start
```

Leave the terminal running while using the app, and open `http://localhost:3000` in the browser. The SQLite database is stored under `DATA_DIR` (default: `data\rolyce-pilot.sqlite`). This local database is only for local development; Vercel uses Cloud Firestore.
The account and login screens require this Node server. Opening `index.html` directly is a local-only preview; it does not create server accounts or sync demo trades.

## Configure Vercel and Firebase

The frontend deploys as static files while the `api/` directory provides Vercel Functions. Account storage uses Cloud Firestore:

1. Open the [Firebase console](https://console.firebase.google.com/), create or select a Firebase project, and enable **Cloud Firestore** in Native mode.
2. In **Project settings → Service accounts**, generate a private key JSON file. Keep this file private.
3. Base64-encode the service-account JSON locally, then add the result as `FIREBASE_SERVICE_ACCOUNT_BASE64` in the Vercel project's Production environment variables. Never commit the key or paste it into chat.
4. Ensure the service account has Firestore data access (for example, the **Cloud Datastore User** role).
5. Redeploy. Firestore collections are created automatically when the API first writes account data.

The API routes are `/api/health`, `/api/auth/login`, `/api/auth/signup`, `/api/auth/me`, `/api/auth/logout`, and `/api/demo`. Without Firebase credentials, they return an explicit configuration error. Vercel's function filesystem is not persistent, so the hosted app does not store accounts in local SQLite.

To base64-encode a downloaded service-account JSON in PowerShell, use its actual file path:

```powershell
$serviceAccount = Get-Content "C:\path\to\service-account.json" -Raw
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($serviceAccount))
```

Copy the printed value directly into Vercel's `FIREBASE_SERVICE_ACCOUNT_BASE64` variable. Treat it as a password.

## Create the administrator login

On a trusted machine, set `FIREBASE_SERVICE_ACCOUNT_BASE64` to the same value configured in Vercel, then run:

```powershell
$env:FIREBASE_SERVICE_ACCOUNT_BASE64 = "your base64 service-account JSON"
npm.cmd install
npm.cmd run admin -- admin
```

This creates a new `admin` account and generates a random password, shown only once in the terminal. Save it in a password manager. You can replace `admin` with another username. The command refuses to overwrite an existing account. Administrator passwords are scrypt-hashed; the admin uses the regular login form.

For accounts in the local SQLite development database instead, use `npm.cmd run admin:local -- admin`. Local SQLite users do not automatically exist in Firebase.

## Issue an invite

Run this command on a trusted machine with the same Firebase service-account environment variable as the deployed app:

```powershell
$env:FIREBASE_SERVICE_ACCOUNT_BASE64 = "your base64 service-account JSON"
npm.cmd run invite -- "customer name or note"
```

The one-time code is printed once, expires after 30 days, and should be sent privately to the invited user. Firestore stores only a hash of the code. Users choose a username and password (minimum 12 characters) when redeeming it. Passwords are scrypt-hashed and login sessions use HttpOnly, SameSite cookies.

## Deployment notes

- For Vercel, set `FIREBASE_SERVICE_ACCOUNT_BASE64` for the Production environment. Vercel provides HTTPS for the app and API routes.
- Keep administrator setup, invite generation access, and service-account credentials private; do not publish them.
- Vercel stores account credentials, sessions, signup-code hashes, and each user's demo account in Firestore. Local development uses SQLite. Demo trades remain simulated and are not broker orders.
- The demo account is for practice only. Live mode embeds a TradingView chart and does not provide live signals or execute real trades.
- This prototype is not financial advice and is not ready to manage customer funds or connect to a broker.
