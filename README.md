# Health MCP Server (Garmin + WHOOP archive)

A remote Model Context Protocol server that gives Claude your Garmin Connect health data, plus a read-only archive of your historical WHOOP data. Hosted on Railway, used as a custom connector in Claude.ai.

## How it works

- **Garmin** — Garmin's official Health API is partner-only, so this uses the unofficial Garmin Connect API via [python-garminconnect](https://github.com/cyberjunky/python-garminconnect), run as a localhost-only Python sidecar (`garmin/bridge.py`) supervised by the Node server. Unofficial means it can break when Garmin changes things; redeploying picks up library fixes (`garmin/requirements.txt` allows minor updates).
- **WHOOP** — kept as a read-only archive in the same SQLite volume. No automatic WHOOP pulls unless `WHOOP_SYNC=on`.
- **Sign-in** — the connector's OAuth flow shows a sign-in page on this server: Garmin email, password, and Garmin's verification code if MFA is on. The password is relayed to Garmin and never stored. The server binds to the first (owner) Garmin account and refuses any other.
- **Writes** — workout, weigh-in and food tools are two-step: without `confirm: true` they validate and return a preview, saving nothing; Claude shows it, then confirms. Exercise names are matched to Garmin's catalogue (case/hyphen-insensitive); unclear names return choices rather than a guess.
- **Storage** — Garmin tokens are AES-GCM encrypted in SQLite (same key as before). Everything else is stored normalised for querying, plus Garmin's raw JSON (large payloads gzipped) so nothing is lost:
  - **Daily** (16 Garmin calls per day): summary, sleep, HRV, training readiness (with factor breakdown), training status and 4-week load balance, all-day heart rate, stress and Body Battery, Body Battery events, respiration, SpO2, 15-minute steps, VO2 max / max metrics, fitness age, hydration, lifestyle logging, all-day events, and the Garmin food log (entries in `garmin_food_entries`, day totals in `garmin_daily.food_*`).
  - **Intraday** (`garmin_intraday`): HR, stress, Body Battery, respiration, SpO2, steps, overnight HRV readings and sleep stages as `[epoch-ms, value]` rows.
  - **Per activity**: full summary (pace, GAP, cadence, stride, ground contact, vertical oscillation/ratio, power, temperature, training-effect messages), laps/km splits, typed splits, HR and power zone time, weather, the recorded time series (up to 4,000 points), and strength exercise sets (exercise, reps, kg).
  - **Profile** (refreshed daily): settings, HR zones, personal records, race predictions (+ a year of history), lactate threshold (+ history), endurance score, hill score, running tolerance, body composition, devices, goals, training plans.
- **Nutrition (Connect+)** — food logging writes go straight to Garmin's `nutrition-service`, which python-garminconnect doesn't wrap. The request shapes follow [garmin_mcp](https://github.com/Taxuspt/garmin_mcp) (MIT), which writes to real accounts under live end-to-end tests: `PUT /nutrition-service/food/logs` with a `mealDate` + `foodLogItems` envelope and the date's numeric `mealId`, `PUT …/food/logs/quickAdd`, `PUT …/customFood`, and `DELETE …/food/logs/{date}` with `{logIds}`. Needs an active Connect+ subscription with nutrition switched on.
- **Sync** — the hourly sync re-pulls today and yesterday, fetches detail for up to 5 new activities, and refreshes profile data once a day. `garmin_sync` with `days` runs a paced background backfill (~15 s per day) that skips days already complete, so it is safe to re-run and resumes after a failure. On a Garmin rate limit it waits 10, 20, then 40 minutes before giving up. Two years of data is roughly 100–200 MB on the volume.

## MCP tools

| Tool | What it returns |
|---|---|
| `garmin_today` | Readiness, last night's sleep + stages, HRV vs baseline, RHR, Body Battery, stress, steps, training status, today's activities |
| `garmin_trends` | Day-by-day table + averages (readiness, HRV, RHR, sleep, Body Battery, stress, steps) |
| `garmin_activities` | Activities with id, time, distance, pace, HR, cadence, training effect, load |
| `garmin_activity_detail` | One activity in depth: running dynamics, weather, HR zones with boundaries, laps, strength sets, first-vs-second-half analysis with aerobic decoupling and HR drift, optional time series |
| `garmin_intraday` | Bucketed intraday HR, stress, Body Battery, respiration, SpO2, steps, overnight HRV, sleep stages (local time) |
| `garmin_profile` | HR zones, race predictions, lactate threshold, VO2 max, settings; any profile dataset as JSON |
| `garmin_records` | Normalised rows as JSON (`daily` or `activities`) |
| `garmin_raw` | Garmin's raw JSON for one date + daily source, or one activity + activity source |
| `garmin_schema` | Tables and columns available to `garmin_query` |
| `garmin_query` | One read-only SQL `SELECT` over the whole database (separate read-only connection; credential tables refused; `gunzip_json(gz)` reads gzipped raw JSON) |
| `garmin_sync` | Refresh now, or `days>7` for a resumable background backfill of everything (`refresh: true` re-fetches stored days) |
| `garmin_auth_url` | Link to reconnect Garmin |
| `garmin_workouts` | Workout library + upcoming calendar entries (with ids) |
| `garmin_create_strength_workout` | Build a strength workout (sets × reps @ kg, rest); optional schedule date / send to watch |
| `garmin_create_run_workout` | Build a structured run (warmup/intervals/recovery/cooldown, pace or HR-zone targets, repeats) |
| `garmin_schedule_workout` | Put a library workout on a calendar date |
| `garmin_remove_workout` | Unschedule one date, or delete from the library |
| `garmin_weigh_ins` | Weigh-ins (weight, BMI, body fat) |
| `garmin_food_search` | Search Garmin's food catalogue (FatSecret + Garmin) and your custom foods; returns food/serving ids with macros |
| `garmin_food_log` | A day's food log by meal with log ids, totals vs Garmin's calorie/macro goals |
| `garmin_food_add` | Log catalogue/custom foods (food id + serving id × servings) to a meal |
| `garmin_food_quick_add` | Quick-add entries by name + calories/macros (e.g. copying a Cronometer day across) |
| `garmin_food_create_custom` | Create a custom food (warns if the name already exists) |
| `garmin_food_remove` | Remove food log entries |
| `garmin_food_copy_day` | Copy a day (or chosen meals) onto another date |
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
| `GARMIN_CALL_GAP_S` | optional | Pause between Garmin calls inside one fetch (default `0.4`) |
| `GARMIN_MAX_CHART` | optional | Max time-series points per activity (default `4000`) |
| `GARMIN_RATE_LIMIT_WAITS_MIN` | optional | Backfill back-off schedule in minutes (default `10,20,40`) |
| `GARMIN_NUTRITION_REGION` / `GARMIN_NUTRITION_LANGUAGE` | optional | Region/language sent with new custom foods and log entries when search didn't supply one (default `US` / `en`, as in garmin_mcp) |
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
