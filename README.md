# Health MCP Server (Garmin + WHOOP archive)

A remote Model Context Protocol server that gives Claude your Garmin Connect health data, plus a read-only archive of your historical WHOOP data. Hosted on Railway, used as a custom connector in Claude.ai.

## How it works

- **Garmin** — Garmin's official Health API is partner-only, so this uses the unofficial Garmin Connect API via [python-garminconnect](https://github.com/cyberjunky/python-garminconnect), run as a localhost-only Python sidecar (`garmin/bridge.py`) supervised by the Node server. Unofficial means it can break when Garmin changes things; redeploying picks up library fixes (`garmin/requirements.txt` allows minor updates).
- **WHOOP** — kept as a read-only archive in the same SQLite volume. No automatic WHOOP pulls unless `WHOOP_SYNC=on`.
- **Sign-in** — the connector's OAuth flow shows a sign-in page on this server: Garmin email, password, and Garmin's verification code if MFA is on. The password is relayed to Garmin and never stored. The server binds to the first (owner) Garmin account and refuses any other.
- **Writes** — workout and weigh-in tools are two-step: without `confirm: true` they validate and return a preview, saving nothing; Claude shows it, then confirms. Exercise names are matched to Garmin's catalogue (case/hyphen-insensitive); unclear names return choices rather than a guess.
- **Storage** — Garmin tokens are AES-GCM encrypted in SQLite (same key as before). Daily metrics are stored normalised plus Garmin's raw JSON per source.

## MCP tools

| Tool | What it returns |
|---|---|
| `garmin_today` | Readiness, last night's sleep + stages, HRV vs baseline, RHR, Body Battery, stress, steps, training status, today's activities |
| `garmin_trends` | Day-by-day table + averages (readiness, HRV, RHR, sleep, Body Battery, stress, steps) |
| `garmin_activities` | Activities with time, distance, HR, training effect, load |
| `garmin_records` | Normalised rows as JSON (`daily` or `activities`) |
| `garmin_raw` | Garmin's raw JSON for one date/source (`summary`, `sleep`, `hrv`, `readiness`, `training_status`) |
| `garmin_sync` | Refresh now, or `days>7` for a paced background backfill |
| `garmin_auth_url` | Link to reconnect Garmin |
| `garmin_workouts` | Workout library + upcoming calendar entries (with ids) |
| `garmin_create_strength_workout` | Build a strength workout (sets × reps @ kg, rest); optional schedule date / send to watch |
| `garmin_create_run_workout` | Build a structured run (warmup/intervals/recovery/cooldown, pace or HR-zone targets, repeats) |
| `garmin_schedule_workout` | Put a library workout on a calendar date |
| `garmin_remove_workout` | Unschedule one date, or delete from the library |
| `garmin_weigh_ins` | Weigh-ins (weight, BMI, body fat) |
| `garmin_log_weight` / `garmin_delete_weight` | Add or remove a weigh-in |
| `whoop_latest`, `whoop_recovery_trends`, `whoop_sleep_analysis`, `whoop_strain_history`, `whoop_records`, `whoop_profile` | WHOOP archive |
| `whoop_sync` | Pull remaining WHOOP data while the WHOOP grant still works |

## Environment variables (Railway)

| Variable | Required | Notes |
|---|---|---|
| `BASE_URL` | yes | Public URL, e.g. `https://…up.railway.app` |
| `GARMIN_OWNER_EMAIL` | yes (first sign-in) | Your Garmin login email. Sign-in fails closed until set |
| `GARMIN_ALLOWED_PROFILE_ID` | optional | Pin the owner by Garmin profile id instead |
| `ENCRYPTION_SECRET` or `WHOOP_CLIENT_SECRET` | yes | Token encryption key — don't change it, or stored tokens become unreadable |
| `SYNC_SECRET` | yes | Shared with the cron service (`trigger-sync.mjs`) |
| `LOCAL_TIMEZONE` | optional | Default `Australia/Brisbane` (defines "today") |
| `WHOOP_SYNC` | optional | `on` resumes automatic WHOOP pulls |
| `WHOOP_CLIENT_ID`, `WHOOP_REDIRECT_URI` | optional | Only needed for `whoop_sync` |

Volume mounted at `/data` (`DB_PATH=/data/whoop.db`).

## Endpoints

- `/mcp` — MCP (Streamable HTTP, OAuth bearer)
- `/reauth` — reconnect Garmin without touching the Claude connector
- `/health` — Garmin connection/sync state and WHOOP archive state
- `POST /sync` — hourly cron target (`x-sync-secret` header); syncs Garmin (and WHOOP if `WHOOP_SYNC=on`)

## Local development

```bash
npm install
python3 -m venv .venv && .venv/bin/pip install -r garmin/requirements.txt
BASE_URL=http://localhost:3000 GARMIN_PYTHON=.venv/bin/python GARMIN_OWNER_EMAIL=you@example.com \
  ENCRYPTION_SECRET=dev SYNC_SECRET=dev npm run dev
```
