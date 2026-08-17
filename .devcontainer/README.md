# Codespace setup — Design Makers

This folder makes the project open-and-run in **GitHub Codespaces** (or
locally in VS Code via "Reopen in Container").

## What it does
- Spins up a **local MongoDB 7** container (data persists in a Docker
  volume across rebuilds, but is separate from your real production DB).
- Installs Node deps automatically (`npm install` on create).
- Forwards port `3000` (the site) and `27017` (Mongo) and auto-opens the
  site preview.

## First run
On the very first boot the local Mongo container is empty, so
`ALLOW_NEW_DATABASE=true` is set for you — the server will create a
fresh database seeded from the code's built-in sample data instead of
crashing. You'll see 29 sample products, not your live 46 — this is a
**local dev database only**, not production.

## Using your real data instead (optional)
If you want to develop against a copy of the live catalog:
1. Comment out / remove `ALLOW_NEW_DATABASE` in `devcontainer.json`.
2. Import `database-backup-2026-08-14.json` into the local Mongo
   container's `designmakers` database, collection matching
   `COLLECTION_NAME` in `database.js`, under `_id: DOC_ID` (check the
   top of `database.js` for the exact constants).

## Pointing at production Mongo (only if you really mean to)
Replace `MONGODB_URI` in `devcontainer.json` → `remoteEnv` with your
real Atlas/Render connection string, and remove
`ALLOW_NEW_DATABASE` entirely. Be careful — this makes the codespace
talk to your **live** database.

## Running the app
```bash
npm install   # already run automatically on container create
npm start     # or: node server.js
```
Then open the forwarded port 3000 preview.
