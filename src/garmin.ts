// src/garmin.ts
//
// Garmin Connect support: a supervisor for the Python bridge sidecar, the SQLite
// storage for Garmin data, and the sync engine.
//
// Garmin's official Health API is partner-only, so this uses the unofficial
// Garmin Connect API through python-garminconnect (garmin/bridge.py). Node owns
// all persistence: the bridge never writes to disk, and Garmin tokens are kept
// AES-GCM encrypted in SQLite alongside the WHOOP archive.

import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { gunzipSync, gzipSync } from 'node:zlib';
import Database from 'better-sqlite3';
import { encrypt, decrypt } from './crypto.js';

// ---------------------------------------------------------------- dates ---

export const LOCAL_TZ = process.env.LOCAL_TIMEZONE ?? 'Australia/Brisbane';

/** Calendar date (YYYY-MM-DD) in the owner's time zone, `daysAgo` days back. */
export function localDate(daysAgo = 0, from = Date.now()): string {
	return new Intl.DateTimeFormat('en-CA', {
		timeZone: LOCAL_TZ,
		year: 'numeric',
		month: '2-digit',
		day: '2-digit',
	}).format(new Date(from - daysAgo * 86_400_000));
}

function addDays(date: string, delta: number): string {
	const d = new Date(`${date}T00:00:00Z`);
	d.setUTCDate(d.getUTCDate() + delta);
	return d.toISOString().slice(0, 10);
}

function dateRange(start: string, end: string): string[] {
	const out: string[] = [];
	for (let d = start; d <= end; d = addDays(d, 1)) out.push(d);
	return out;
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// --------------------------------------------------------------- bridge ---

export class GarminBridgeError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
		message: string
	) {
		super(message);
		this.name = 'GarminBridgeError';
	}
}

export interface GarminAccount {
	profile_id: number | null;
	display_name: string | null;
	full_name: string | null;
}

interface BridgeOptions {
	python: string;
	script: string;
	onTokens: (tokens: string) => void;
	loadTokens: () => string | null;
}

export class GarminBridge {
	private proc: ChildProcess | null = null;
	private port: number | null = null;
	private starting: Promise<void> | null = null;
	private readonly secret = randomBytes(32).toString('hex');

	constructor(private readonly opts: BridgeOptions) {}

	/** Start the sidecar now (optional — calls start it lazily). */
	warmUp(): void {
		this.ensure().catch(err => console.error('[garmin] bridge failed to start:', err instanceof Error ? err.message : err));
	}

	async call<T = Record<string, unknown>>(path: string, body: unknown = {}, timeoutMs = 90_000): Promise<T> {
		await this.ensure();
		return this.request<T>(path, body, timeoutMs);
	}

	stop(): void {
		this.proc?.kill('SIGTERM');
	}

	private ensure(): Promise<void> {
		if (this.proc && this.port) return Promise.resolve();
		if (!this.starting) {
			this.starting = this.start().finally(() => {
				this.starting = null;
			});
		}
		return this.starting;
	}

	private async start(): Promise<void> {
		if (!existsSync(this.opts.script)) {
			throw new Error(`Garmin bridge script not found at ${this.opts.script}`);
		}
		const proc = spawn(this.opts.python, [this.opts.script], {
			// TZ makes the bridge's local-time maths (weigh-in timestamps) use the owner's zone.
			env: { ...process.env, BRIDGE_SECRET: this.secret, PYTHONUNBUFFERED: '1', TZ: LOCAL_TZ },
			stdio: ['ignore', 'pipe', 'pipe'],
		});

		proc.stderr?.on('data', chunk => process.stderr.write(String(chunk)));
		proc.on('exit', code => {
			console.error(`[garmin] bridge exited (code ${code}); it restarts on next use`);
			if (this.proc === proc) {
				this.proc = null;
				this.port = null;
			}
		});

		const port = await new Promise<number>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error('Garmin bridge did not start within 30s')), 30_000);
			proc.once('error', err => {
				clearTimeout(timer);
				reject(err);
			});
			proc.once('exit', code => {
				clearTimeout(timer);
				reject(new Error(`Garmin bridge exited during startup (code ${code})`));
			});
			const lines = createInterface({ input: proc.stdout! });
			lines.on('line', line => {
				const match = /^READY (\d+)$/.exec(line.trim());
				if (match) {
					clearTimeout(timer);
					resolve(Number(match[1]));
				}
			});
		});

		this.proc = proc;
		this.port = port;

		// Restore the saved Garmin session so the bridge is usable straight away.
		const tokens = this.opts.loadTokens();
		if (tokens) {
			try {
				await this.request('/session/load', { tokens }, 60_000);
				console.log('[garmin] session restored');
			} catch (err) {
				console.error('[garmin] saved session could not be restored — sign in again at /reauth:', err instanceof Error ? err.message : err);
			}
		}
	}

	private async request<T>(path: string, body: unknown, timeoutMs: number): Promise<T> {
		if (!this.port) throw new GarminBridgeError(503, 'bridge_down', 'Garmin bridge is not running');
		let res: globalThis.Response;
		try {
			res = await fetch(`http://127.0.0.1:${this.port}${path}`, {
				method: 'POST',
				headers: { 'content-type': 'application/json', 'x-bridge-secret': this.secret },
				body: JSON.stringify(body ?? {}),
				signal: AbortSignal.timeout(timeoutMs),
			});
		} catch (err) {
			throw new GarminBridgeError(503, 'bridge_unreachable', `Garmin bridge unreachable: ${err instanceof Error ? err.message : err}`);
		}
		const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
		if (typeof json.tokens === 'string' && json.tokens) {
			try {
				this.opts.onTokens(json.tokens);
			} catch (err) {
				console.error('[garmin] failed to persist refreshed tokens', err instanceof Error ? err.message : err);
			}
			delete json.tokens;
		}
		if (!res.ok) {
			throw new GarminBridgeError(res.status, String(json.error ?? 'error'), String(json.message ?? `bridge HTTP ${res.status}`));
		}
		return json as T;
	}
}

// ---------------------------------------------------------------- store ---

type ColType = 'INTEGER' | 'REAL' | 'TEXT';

// Normalised daily columns. Keep in step with normalise_daily() in bridge.py.
const DAILY_COLUMNS: Record<string, ColType> = {
	steps: 'INTEGER', distance_m: 'REAL', resting_hr: 'INTEGER', min_hr: 'INTEGER', max_hr: 'INTEGER',
	total_kcal: 'REAL', active_kcal: 'REAL', intensity_moderate_min: 'INTEGER', intensity_vigorous_min: 'INTEGER',
	stress_avg: 'INTEGER', stress_max: 'INTEGER',
	bb_high: 'INTEGER', bb_low: 'INTEGER', bb_charged: 'INTEGER', bb_drained: 'INTEGER', bb_wake: 'INTEGER',
	spo2_avg: 'REAL', spo2_low: 'REAL', resp_waking: 'REAL',
	sleep_s: 'INTEGER', deep_s: 'INTEGER', light_s: 'INTEGER', rem_s: 'INTEGER', awake_s: 'INTEGER',
	sleep_start_gmt: 'INTEGER', sleep_end_gmt: 'INTEGER', sleep_score: 'INTEGER', sleep_quality: 'TEXT',
	sleep_resp_avg: 'REAL', sleep_stress_avg: 'REAL', sleep_spo2_avg: 'REAL',
	hrv_last_night: 'REAL', hrv_5min_high: 'REAL', hrv_weekly: 'REAL', hrv_status: 'TEXT',
	hrv_baseline_low: 'REAL', hrv_baseline_high: 'REAL',
	readiness_score: 'INTEGER', readiness_level: 'TEXT', readiness_feedback: 'TEXT', recovery_time_min: 'INTEGER',
	training_status: 'TEXT', load_acute: 'REAL', load_chronic: 'REAL', acwr: 'REAL', vo2max: 'REAL',
	// added with the full-capture sync
	step_goal: 'INTEGER', floors_up: 'REAL', floors_down: 'REAL', bmr_kcal: 'REAL',
	active_s: 'INTEGER', highly_active_s: 'INTEGER', sedentary_s: 'INTEGER',
	stress_rest_s: 'INTEGER', stress_low_s: 'INTEGER', stress_medium_s: 'INTEGER', stress_high_s: 'INTEGER', stress_qualifier: 'TEXT',
	nap_s: 'INTEGER', sleep_start_local: 'INTEGER', sleep_end_local: 'INTEGER', sleep_hrv_avg: 'REAL', sleep_avg_hr: 'REAL',
	sleep_resp_low: 'REAL', sleep_resp_high: 'REAL', sleep_awake_count: 'INTEGER', sleep_restless_moments: 'INTEGER',
	sleep_bb_change: 'INTEGER', sleep_need_min: 'INTEGER', sleep_feedback: 'TEXT',
	sleep_deep_pct: 'REAL', sleep_light_pct: 'REAL', sleep_rem_pct: 'REAL',
	sleep_q_duration: 'TEXT', sleep_q_stress: 'TEXT', sleep_q_restlessness: 'TEXT',
	hrv_feedback: 'TEXT', readiness_sleep_score: 'INTEGER', readiness_sleep_pct: 'REAL', readiness_sleep_history_pct: 'REAL',
	readiness_recovery_pct: 'REAL', readiness_acwr_pct: 'REAL', readiness_hrv_pct: 'REAL', readiness_stress_pct: 'REAL',
	readiness_feedback_long: 'TEXT',
	load_aerobic_low: 'REAL', load_aerobic_high: 'REAL', load_anaerobic: 'REAL', load_balance_feedback: 'TEXT',
	fitness_age: 'REAL', fitness_age_achievable: 'REAL', hydration_ml: 'REAL', hydration_goal_ml: 'REAL', sweat_loss_ml: 'REAL',
	food_kcal: 'REAL', food_protein_g: 'REAL', food_carbs_g: 'REAL', food_fat_g: 'REAL', food_fiber_g: 'REAL', food_items: 'INTEGER',
};

/** Daily columns derived from the food log — refreshed on their own after a nutrition write. */
const FOOD_DAILY_COLUMNS = ['food_kcal', 'food_protein_g', 'food_carbs_g', 'food_fat_g', 'food_fiber_g', 'food_items'] as const;

const FOOD_ENTRY_COLUMNS: Record<string, ColType> = {
	date: 'TEXT', meal: 'TEXT', meal_time: 'TEXT', name: 'TEXT', brand: 'TEXT', category: 'TEXT',
	food_id: 'TEXT', serving_id: 'TEXT', source: 'TEXT', servings: 'REAL', serving_unit: 'TEXT', serving_units: 'REAL',
	kcal: 'REAL', protein_g: 'REAL', carbs_g: 'REAL', fat_g: 'REAL', fiber_g: 'REAL', sugar_g: 'REAL', sat_fat_g: 'REAL', sodium_mg: 'REAL',
	logged_at: 'TEXT',
};

export type FoodEntry = { log_id: string } & Record<string, string | number | null>;

const toNum = (v: unknown): number | null => {
	const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
	return typeof n === 'number' && Number.isFinite(n) ? n : null;
};

/** Flatten Garmin's food log ({mealDetails: [{meal, loggedFoods}]}) into entries with consumed amounts. */
export function parseFoodLog(date: string, log: unknown): FoodEntry[] {
	const out: FoodEntry[] = [];
	const details = (log as { mealDetails?: unknown } | null)?.mealDetails;
	for (const md of Array.isArray(details) ? details : []) {
		const meal = (md as { meal?: { mealName?: unknown } })?.meal?.mealName;
		const foods = (md as { loggedFoods?: unknown })?.loggedFoods;
		for (const f of Array.isArray(foods) ? (foods as Array<Record<string, unknown>>) : []) {
			if (typeof f?.logId !== 'string') continue;
			const meta = (f.foodMetaData ?? {}) as Record<string, unknown>;
			const nc = (f.nutritionContent ?? {}) as Record<string, unknown>;
			const qty = toNum(f.servingQty) ?? 1;
			// nutritionContent is per serving; servingQty multiplies it. Quick adds may carry totals on the entry itself.
			const amt = (k: string) => {
				const per = toNum(nc[k]);
				if (per != null) return Math.round(per * qty * 100) / 100;
				return toNum(f[k]);
			};
			out.push({
				log_id: f.logId,
				date,
				meal: typeof meal === 'string' ? meal : null,
				meal_time: typeof f.mealTime === 'string' ? f.mealTime : null,
				name: String(meta.foodName ?? f.name ?? '') || null,
				brand: typeof meta.brandName === 'string' ? meta.brandName : null,
				category: typeof f.logCategory === 'string' ? f.logCategory : null,
				food_id: meta.foodId != null ? String(meta.foodId) : null,
				serving_id: nc.servingId != null ? String(nc.servingId) : null,
				source: typeof meta.source === 'string' ? meta.source : null,
				servings: qty,
				serving_unit: typeof nc.servingUnit === 'string' ? nc.servingUnit : null,
				serving_units: toNum(nc.numberOfUnits),
				kcal: amt('calories'),
				protein_g: amt('protein'),
				carbs_g: amt('carbs'),
				fat_g: amt('fat'),
				fiber_g: amt('fiber'),
				sugar_g: amt('sugar'),
				sat_fat_g: amt('saturatedFat'),
				sodium_mg: amt('sodium'),
				logged_at: typeof f.logTimestamp === 'string' ? f.logTimestamp : null,
			});
		}
	}
	return out;
}

// Keep in step with normalise_activity() / _ACTIVITY_EXTRA_FIELDS in bridge.py.
const ACTIVITY_COLUMNS: Record<string, ColType> = {
	name: 'TEXT', type_key: 'TEXT', start_local: 'TEXT', start_gmt: 'TEXT',
	duration_s: 'REAL', moving_s: 'REAL', distance_m: 'REAL', avg_hr: 'REAL', max_hr: 'REAL', kcal: 'REAL',
	aerobic_te: 'REAL', anaerobic_te: 'REAL', training_load: 'REAL', avg_speed: 'REAL', elevation_gain: 'REAL',
	z1_s: 'REAL', z2_s: 'REAL', z3_s: 'REAL', z4_s: 'REAL', z5_s: 'REAL',
	// added with the full-capture sync
	elapsed_s: 'REAL', max_speed: 'REAL', elevation_loss: 'REAL', min_elevation: 'REAL', max_elevation: 'REAL',
	avg_cadence: 'REAL', max_cadence: 'REAL', stride_cm: 'REAL', gct_ms: 'REAL', vert_osc_cm: 'REAL', vert_ratio: 'REAL',
	avg_power: 'REAL', max_power: 'REAL', norm_power: 'REAL', gap_speed: 'REAL', avg_resp: 'REAL', min_hr: 'REAL',
	vo2max: 'REAL', te_label: 'TEXT', aerobic_te_msg: 'TEXT', anaerobic_te_msg: 'TEXT', min_temp_c: 'REAL', max_temp_c: 'REAL',
	steps: 'REAL', bb_change: 'REAL', intensity_moderate_min: 'REAL', intensity_vigorous_min: 'REAL', sweat_ml: 'REAL',
	total_sets: 'REAL', active_sets: 'REAL', total_reps: 'REAL', total_volume: 'REAL', lap_count: 'REAL',
	location: 'TEXT', description: 'TEXT',
};

const LAP_COLUMNS: Record<string, ColType> = {
	start_gmt: 'TEXT', duration_s: 'REAL', moving_s: 'REAL', distance_m: 'REAL', avg_speed: 'REAL', gap_speed: 'REAL',
	max_speed: 'REAL', avg_hr: 'REAL', max_hr: 'REAL', avg_cadence: 'REAL', max_cadence: 'REAL', stride_cm: 'REAL',
	gct_ms: 'REAL', vert_osc_cm: 'REAL', vert_ratio: 'REAL', avg_power: 'REAL', elevation_gain: 'REAL',
	elevation_loss: 'REAL', kcal: 'REAL', intensity: 'TEXT',
};

const SET_COLUMNS: Record<string, ColType> = {
	set_type: 'TEXT', category: 'TEXT', exercise: 'TEXT', reps: 'REAL', weight_kg: 'REAL', duration_s: 'REAL', start_gmt: 'TEXT',
};

/** Per-day Garmin sources (one call each). Keep in step with _daily_calls() in bridge.py. */
export const DAILY_SOURCES = [
	'summary', 'sleep', 'hrv', 'readiness', 'training_status',
	'heart_rates', 'stress', 'body_battery_events', 'respiration', 'spo2', 'steps',
	'max_metrics', 'fitness_age', 'hydration', 'lifestyle', 'all_day_events', 'food_log',
] as const;
export type DailySource = (typeof DAILY_SOURCES)[number];
/** Back-compat alias. */
export const RAW_SOURCES = DAILY_SOURCES;
export type RawSource = DailySource;

/** Large intraday payloads are stored gzipped; their series also land in garmin_intraday. */
const GZ_DAILY_SOURCES = new Set<string>(['sleep', 'heart_rates', 'stress', 'respiration', 'spo2', 'steps']);

export const ACTIVITY_SOURCES = ['summary', 'splits', 'typed_splits', 'split_summaries', 'hr_zones', 'power_zones', 'weather', 'details', 'exercise_sets'] as const;
export type ActivitySource = (typeof ACTIVITY_SOURCES)[number];

export const INTRADAY_METRICS = ['hr', 'stress', 'body_battery', 'respiration', 'spo2', 'spo2_hourly', 'steps', 'hrv', 'sleep_stage'] as const;
export type IntradayMetric = (typeof INTRADAY_METRICS)[number];

/** Tables the read-only query tool must never touch (credentials). */
const PRIVATE_TABLES = /\b(tokens|garmin_account|oauth_[a-z_]+)\b/i;

export type GarminDailyRow = { date: string; synced_at: string; errors: string | null } & Record<string, unknown>;
export type GarminActivityRow = { activity_id: number; synced_at: string } & Record<string, unknown>;

function cell(value: unknown): string | number | null {
	if (value === null || value === undefined) return null;
	if (typeof value === 'number') return Number.isFinite(value) ? value : null;
	if (typeof value === 'boolean') return value ? 1 : 0;
	return String(value);
}

const gz = (value: unknown): Buffer | null => (value == null ? null : gzipSync(Buffer.from(JSON.stringify(value))));
const ungz = (buf: Buffer | null | undefined): unknown => (buf == null ? null : JSON.parse(gunzipSync(buf).toString('utf8')));

const colsSql = (cols: Record<string, ColType>) => Object.entries(cols).map(([n, t]) => `${n} ${t}`).join(',\n');

export interface ActivityDetailResponse {
	activity_id: number;
	extras: Record<string, unknown>;
	laps: Array<Record<string, unknown>>;
	sets: Array<Record<string, unknown>>;
	zones: Array<{ zone: number; secs: number | null; low: number | null }>;
	raw: Record<string, unknown>;
	errors: Record<string, string>;
}

export class GarminStore {
	private readonly db: Database.Database;
	private ro: Database.Database | null = null;

	constructor(private readonly dbPath: string) {
		this.db = new Database(dbPath);
		this.db.pragma('journal_mode = WAL');
		this.db.pragma('busy_timeout = 5000');

		this.db.exec(`
			CREATE TABLE IF NOT EXISTS garmin_account (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				profile_id INTEGER,
				display_name TEXT,
				full_name TEXT,
				tokens TEXT,
				tokens_updated_at TEXT,
				bound_at TEXT
			);
			CREATE TABLE IF NOT EXISTS garmin_daily (
				date TEXT PRIMARY KEY,
				${colsSql(DAILY_COLUMNS)},
				errors TEXT,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);
			CREATE TABLE IF NOT EXISTS garmin_daily_raw (
				date TEXT NOT NULL,
				source TEXT NOT NULL,
				json TEXT,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY (date, source)
			);
			CREATE TABLE IF NOT EXISTS garmin_intraday (
				date TEXT NOT NULL,
				metric TEXT NOT NULL,
				ts INTEGER NOT NULL,
				value REAL,
				PRIMARY KEY (date, metric, ts)
			) WITHOUT ROWID;
			CREATE TABLE IF NOT EXISTS garmin_activities (
				activity_id INTEGER PRIMARY KEY,
				${colsSql(ACTIVITY_COLUMNS)},
				raw TEXT,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);
			CREATE INDEX IF NOT EXISTS idx_garmin_activities_start ON garmin_activities(start_local);
			CREATE TABLE IF NOT EXISTS garmin_activity_detail_state (
				activity_id INTEGER PRIMARY KEY,
				errors TEXT,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);
			CREATE TABLE IF NOT EXISTS garmin_activity_raw (
				activity_id INTEGER NOT NULL,
				source TEXT NOT NULL,
				gz BLOB,
				PRIMARY KEY (activity_id, source)
			);
			CREATE TABLE IF NOT EXISTS garmin_activity_laps (
				activity_id INTEGER NOT NULL,
				lap_index INTEGER NOT NULL,
				${colsSql(LAP_COLUMNS)},
				PRIMARY KEY (activity_id, lap_index)
			);
			CREATE TABLE IF NOT EXISTS garmin_activity_sets (
				activity_id INTEGER NOT NULL,
				set_index INTEGER NOT NULL,
				${colsSql(SET_COLUMNS)},
				PRIMARY KEY (activity_id, set_index)
			);
			CREATE TABLE IF NOT EXISTS garmin_activity_zones (
				activity_id INTEGER NOT NULL,
				zone INTEGER NOT NULL,
				secs REAL,
				low_bpm REAL,
				PRIMARY KEY (activity_id, zone)
			);
			CREATE TABLE IF NOT EXISTS garmin_food_entries (
				log_id TEXT PRIMARY KEY,
				${colsSql(FOOD_ENTRY_COLUMNS)}
			);
			CREATE INDEX IF NOT EXISTS idx_garmin_food_entries_date ON garmin_food_entries(date);
			CREATE TABLE IF NOT EXISTS garmin_snapshots (
				kind TEXT PRIMARY KEY,
				json TEXT,
				error TEXT,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);
			CREATE TABLE IF NOT EXISTS garmin_sync_state (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				last_sync_at TEXT,
				oldest_date TEXT,
				newest_date TEXT,
				last_error TEXT
			);
			INSERT OR IGNORE INTO garmin_sync_state (id) VALUES (1);
			INSERT OR IGNORE INTO garmin_account (id) VALUES (1);
		`);
		this.migrate('garmin_daily', DAILY_COLUMNS);
		this.migrate('garmin_activities', ACTIVITY_COLUMNS);
		this.migrate('garmin_daily_raw', { gz: 'BLOB' as ColType, error: 'TEXT' });
		this.migrate('garmin_activity_laps', LAP_COLUMNS);
		this.migrate('garmin_activity_sets', SET_COLUMNS);
		this.migrate('garmin_food_entries', FOOD_ENTRY_COLUMNS);
	}

	private migrate(table: string, columns: Record<string, string>): void {
		const existing = new Set((this.db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map(c => c.name));
		for (const [name, type] of Object.entries(columns)) {
			if (!existing.has(name)) this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
		}
	}

	// ---- account & tokens --------------------------------------------------

	getAccount(): (GarminAccount & { bound_at: string | null; tokens_updated_at: string | null }) | null {
		const row = this.db.prepare('SELECT profile_id, display_name, full_name, bound_at, tokens_updated_at FROM garmin_account WHERE id = 1').get() as
			| (GarminAccount & { bound_at: string | null; tokens_updated_at: string | null })
			| undefined;
		return row?.profile_id != null ? row : null;
	}

	bindAccount(account: GarminAccount): void {
		this.db.prepare(`
			UPDATE garmin_account
			SET profile_id = ?, display_name = ?, full_name = ?, bound_at = COALESCE(bound_at, CURRENT_TIMESTAMP)
			WHERE id = 1
		`).run(account.profile_id, account.display_name, account.full_name);
	}

	saveTokens(tokens: string): void {
		this.db.prepare('UPDATE garmin_account SET tokens = ?, tokens_updated_at = CURRENT_TIMESTAMP WHERE id = 1').run(encrypt(tokens));
	}

	getTokens(): string | null {
		const row = this.db.prepare('SELECT tokens FROM garmin_account WHERE id = 1').get() as { tokens: string | null } | undefined;
		if (!row?.tokens) return null;
		try {
			return decrypt(row.tokens);
		} catch (err) {
			console.error('[garmin] stored tokens could not be decrypted (encryption secret changed?)', err instanceof Error ? err.message : err);
			return null;
		}
	}

	// ---- daily -------------------------------------------------------------

	upsertDaily(
		norm: Record<string, unknown>,
		raw: Record<string, unknown>,
		errors: Record<string, string>,
		intraday: Record<string, Array<[number, number]>> = {}
	): void {
		const cols = Object.keys(DAILY_COLUMNS);
		const stmt = this.db.prepare(`
			INSERT OR REPLACE INTO garmin_daily (date, ${cols.join(', ')}, errors, synced_at)
			VALUES (?, ${cols.map(() => '?').join(', ')}, ?, CURRENT_TIMESTAMP)
		`);
		const rawStmt = this.db.prepare(`
			INSERT OR REPLACE INTO garmin_daily_raw (date, source, json, gz, error, synced_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		`);
		const delIntra = this.db.prepare('DELETE FROM garmin_intraday WHERE date = ? AND metric = ?');
		const insIntra = this.db.prepare('INSERT OR REPLACE INTO garmin_intraday (date, metric, ts, value) VALUES (?, ?, ?, ?)');
		const date = String(norm.date);
		this.db.transaction(() => {
			stmt.run(date, ...cols.map(c => cell(norm[c])), Object.keys(errors).length ? JSON.stringify(errors) : null);
			for (const source of DAILY_SOURCES) {
				if (!(source in raw)) continue; // not fetched this time — keep what's stored
				const value = raw[source];
				const zipped = GZ_DAILY_SOURCES.has(source);
				rawStmt.run(date, source, zipped || value == null ? null : JSON.stringify(value), zipped ? gz(value) : null, errors[source] ?? null);
			}
			if ('food_log' in raw && !errors.food_log) this.replaceFoodEntries(date, raw.food_log);
			for (const [metric, points] of Object.entries(intraday)) {
				if (!Array.isArray(points) || !points.length) continue;
				delIntra.run(date, metric);
				for (const [ts, value] of points) insIntra.run(date, metric, Math.trunc(ts), value);
			}
		})();
	}

	private replaceFoodEntries(date: string, log: unknown): void {
		const cols = Object.keys(FOOD_ENTRY_COLUMNS);
		this.db.prepare('DELETE FROM garmin_food_entries WHERE date = ?').run(date);
		const stmt = this.db.prepare(`INSERT OR REPLACE INTO garmin_food_entries (log_id, ${cols.join(', ')}) VALUES (?, ${cols.map(() => '?').join(', ')})`);
		for (const e of parseFoodLog(date, log)) stmt.run(e.log_id, ...cols.map(c => cell(e[c])));
	}

	/**
	 * Store a freshly read food log for one date (after a nutrition write) without
	 * touching the day's other metrics.
	 */
	upsertFoodLog(date: string, log: unknown, totals: Record<string, unknown>): void {
		this.db.transaction(() => {
			this.db.prepare('INSERT OR REPLACE INTO garmin_daily_raw (date, source, json, gz, error, synced_at) VALUES (?, ?, ?, NULL, NULL, CURRENT_TIMESTAMP)').run(
				date,
				'food_log',
				log == null ? null : JSON.stringify(log)
			);
			this.replaceFoodEntries(date, log);
			this.db.prepare('INSERT OR IGNORE INTO garmin_daily (date) VALUES (?)').run(date);
			this.db.prepare(`UPDATE garmin_daily SET ${FOOD_DAILY_COLUMNS.map(c => `${c} = ?`).join(', ')} WHERE date = ?`).run(
				...FOOD_DAILY_COLUMNS.map(c => cell(totals[c])),
				date
			);
		})();
	}

	getFoodEntries(date: string): FoodEntry[] {
		return this.db.prepare('SELECT * FROM garmin_food_entries WHERE date = ? ORDER BY meal_time, logged_at').all(date) as FoodEntry[];
	}

	getDaily(date: string): GarminDailyRow | null {
		return (this.db.prepare('SELECT * FROM garmin_daily WHERE date = ?').get(date) as GarminDailyRow | undefined) ?? null;
	}

	getLatestDaily(): GarminDailyRow | null {
		return (this.db.prepare('SELECT * FROM garmin_daily ORDER BY date DESC LIMIT 1').get() as GarminDailyRow | undefined) ?? null;
	}

	getDailyRange(start: string, end: string): GarminDailyRow[] {
		return this.db.prepare('SELECT * FROM garmin_daily WHERE date >= ? AND date <= ? ORDER BY date DESC').all(start, end) as GarminDailyRow[];
	}

	getRaw(date: string, source: string): unknown {
		const row = this.db.prepare('SELECT json, gz FROM garmin_daily_raw WHERE date = ? AND source = ?').get(date, source) as
			| { json: string | null; gz: Buffer | null }
			| undefined;
		if (!row) return undefined;
		if (row.gz) return ungz(row.gz);
		return row.json == null ? null : JSON.parse(row.json);
	}

	/** Dates in [start, end] that are missing any daily source. */
	incompleteDays(start: string, end: string): string[] {
		const have = this.db.prepare(`
			SELECT date, COUNT(DISTINCT source) AS n FROM garmin_daily_raw
			WHERE date >= ? AND date <= ? AND source IN (${DAILY_SOURCES.map(() => '?').join(', ')})
			GROUP BY date
		`).all(start, end, ...DAILY_SOURCES) as Array<{ date: string; n: number }>;
		const complete = new Set(have.filter(r => r.n >= DAILY_SOURCES.length).map(r => r.date));
		return dateRange(start, end).filter(d => !complete.has(d));
	}

	getIntraday(start: string, end: string, metric: string): Array<{ date: string; ts: number; value: number }> {
		return this.db.prepare('SELECT date, ts, value FROM garmin_intraday WHERE metric = ? AND date >= ? AND date <= ? ORDER BY ts').all(metric, start, end) as Array<{
			date: string;
			ts: number;
			value: number;
		}>;
	}

	// ---- activities --------------------------------------------------------

	upsertActivities(items: Array<{ normalised: Record<string, unknown>; raw: unknown }>): void {
		const cols = Object.keys(ACTIVITY_COLUMNS);
		// Upsert so a list refresh never wipes values filled in from activity detail.
		const stmt = this.db.prepare(`
			INSERT INTO garmin_activities (activity_id, ${cols.join(', ')}, raw, synced_at)
			VALUES (?, ${cols.map(() => '?').join(', ')}, ?, CURRENT_TIMESTAMP)
			ON CONFLICT(activity_id) DO UPDATE SET
				${cols.map(c => `${c} = COALESCE(excluded.${c}, garmin_activities.${c})`).join(',\n')},
				raw = excluded.raw,
				synced_at = CURRENT_TIMESTAMP
		`);
		this.db.transaction(() => {
			for (const { normalised, raw } of items) {
				stmt.run(cell(normalised.activity_id), ...cols.map(c => cell(normalised[c])), JSON.stringify(raw));
			}
		})();
	}

	getActivitiesRange(start: string, end: string, includeRaw = false): GarminActivityRow[] {
		const select = includeRaw ? '*' : `activity_id, ${Object.keys(ACTIVITY_COLUMNS).join(', ')}, synced_at`;
		// start_local is "YYYY-MM-DD HH:MM:SS" local time; compare on its date part.
		return this.db.prepare(`
			SELECT ${select} FROM garmin_activities
			WHERE substr(start_local, 1, 10) >= ? AND substr(start_local, 1, 10) <= ?
			ORDER BY start_local DESC
		`).all(start, end) as GarminActivityRow[];
	}

	getActivity(activityId: number): GarminActivityRow | null {
		return (this.db.prepare(`SELECT activity_id, ${Object.keys(ACTIVITY_COLUMNS).join(', ')}, synced_at FROM garmin_activities WHERE activity_id = ?`).get(activityId) as
			| GarminActivityRow
			| undefined) ?? null;
	}

	/** Activities whose detail (laps, zones, series…) hasn't been fetched yet, newest first. */
	activitiesNeedingDetail(limit = 10_000): Array<{ activity_id: number; type_key: string | null; total_sets: number | null }> {
		return this.db.prepare(`
			SELECT a.activity_id, a.type_key, a.total_sets FROM garmin_activities a
			LEFT JOIN garmin_activity_detail_state s ON s.activity_id = a.activity_id
			WHERE s.activity_id IS NULL
			ORDER BY a.start_local DESC
			LIMIT ?
		`).all(limit) as Array<{ activity_id: number; type_key: string | null; total_sets: number | null }>;
	}

	upsertActivityDetail(res: ActivityDetailResponse): void {
		const id = res.activity_id;
		const extras = Object.entries(res.extras).filter(([k, v]) => k in ACTIVITY_COLUMNS && v != null);
		const lapCols = Object.keys(LAP_COLUMNS);
		const setCols = Object.keys(SET_COLUMNS);
		this.db.transaction(() => {
			if (extras.length) {
				// The list response wins where it has a value; detail fills the gaps.
				this.db.prepare(`UPDATE garmin_activities SET ${extras.map(([k]) => `${k} = COALESCE(${k}, ?)`).join(', ')} WHERE activity_id = ?`).run(
					...extras.map(([, v]) => cell(v)),
					id
				);
			}
			const rawStmt = this.db.prepare('INSERT OR REPLACE INTO garmin_activity_raw (activity_id, source, gz) VALUES (?, ?, ?)');
			for (const [source, value] of Object.entries(res.raw)) rawStmt.run(id, source, gz(value));

			this.db.prepare('DELETE FROM garmin_activity_laps WHERE activity_id = ?').run(id);
			const lapStmt = this.db.prepare(`INSERT OR REPLACE INTO garmin_activity_laps (activity_id, lap_index, ${lapCols.join(', ')}) VALUES (?, ?, ${lapCols.map(() => '?').join(', ')})`);
			for (const lap of res.laps) lapStmt.run(id, cell(lap.lap_index), ...lapCols.map(c => cell(lap[c])));

			this.db.prepare('DELETE FROM garmin_activity_sets WHERE activity_id = ?').run(id);
			const setStmt = this.db.prepare(`INSERT OR REPLACE INTO garmin_activity_sets (activity_id, set_index, ${setCols.join(', ')}) VALUES (?, ?, ${setCols.map(() => '?').join(', ')})`);
			for (const s of res.sets) setStmt.run(id, cell(s.set_index), ...setCols.map(c => cell(s[c])));

			this.db.prepare('DELETE FROM garmin_activity_zones WHERE activity_id = ?').run(id);
			const zoneStmt = this.db.prepare('INSERT OR REPLACE INTO garmin_activity_zones (activity_id, zone, secs, low_bpm) VALUES (?, ?, ?, ?)');
			for (const z of res.zones) zoneStmt.run(id, cell(z.zone), cell(z.secs), cell(z.low));

			this.db.prepare('INSERT OR REPLACE INTO garmin_activity_detail_state (activity_id, errors, synced_at) VALUES (?, ?, CURRENT_TIMESTAMP)').run(
				id,
				Object.keys(res.errors).length ? JSON.stringify(res.errors) : null
			);
		})();
	}

	getActivityDetailState(activityId: number): { errors: string | null; synced_at: string } | null {
		return (this.db.prepare('SELECT errors, synced_at FROM garmin_activity_detail_state WHERE activity_id = ?').get(activityId) as
			| { errors: string | null; synced_at: string }
			| undefined) ?? null;
	}

	getActivityLaps(activityId: number): Array<Record<string, unknown>> {
		return this.db.prepare('SELECT * FROM garmin_activity_laps WHERE activity_id = ? ORDER BY lap_index').all(activityId) as Array<Record<string, unknown>>;
	}

	getActivitySets(activityId: number): Array<Record<string, unknown>> {
		return this.db.prepare('SELECT * FROM garmin_activity_sets WHERE activity_id = ? ORDER BY set_index').all(activityId) as Array<Record<string, unknown>>;
	}

	getActivityZones(activityId: number): Array<{ zone: number; secs: number | null; low_bpm: number | null }> {
		return this.db.prepare('SELECT zone, secs, low_bpm FROM garmin_activity_zones WHERE activity_id = ? ORDER BY zone').all(activityId) as Array<{
			zone: number;
			secs: number | null;
			low_bpm: number | null;
		}>;
	}

	getActivityRaw(activityId: number, source: string): unknown {
		const row = this.db.prepare('SELECT gz FROM garmin_activity_raw WHERE activity_id = ? AND source = ?').get(activityId, source) as { gz: Buffer | null } | undefined;
		if (!row) return undefined;
		return ungz(row.gz);
	}

	// ---- snapshots (profile-level data) ------------------------------------

	upsertSnapshots(snapshots: Record<string, unknown>, errors: Record<string, string>): void {
		const stmt = this.db.prepare('INSERT OR REPLACE INTO garmin_snapshots (kind, json, error, synced_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)');
		this.db.transaction(() => {
			for (const [kind, value] of Object.entries(snapshots)) {
				// Keep the last good copy if this refresh failed for one kind.
				if (value == null && errors[kind]) {
					this.db.prepare('UPDATE garmin_snapshots SET error = ? WHERE kind = ?').run(errors[kind], kind);
					if (this.getSnapshot(kind) !== undefined) continue;
				}
				stmt.run(kind, value == null ? null : JSON.stringify(value), errors[kind] ?? null);
			}
		})();
	}

	getSnapshot(kind: string): unknown {
		const row = this.db.prepare('SELECT json FROM garmin_snapshots WHERE kind = ?').get(kind) as { json: string | null } | undefined;
		if (!row) return undefined;
		return row.json == null ? null : JSON.parse(row.json);
	}

	snapshotsAgeHours(): number | null {
		const row = this.db.prepare('SELECT MAX(synced_at) AS t FROM garmin_snapshots').get() as { t: string | null };
		if (!row?.t) return null;
		return (Date.now() - Date.parse(`${row.t.replace(' ', 'T')}Z`)) / 3_600_000;
	}

	// ---- analysis ----------------------------------------------------------

	/** Table/column listing for the query tool (credential tables excluded). */
	schema(): Array<{ table: string; rows: number; columns: string[] }> {
		const tables = this.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as Array<{ name: string }>;
		return tables
			.filter(t => !PRIVATE_TABLES.test(t.name))
			.map(t => ({
				table: t.name,
				rows: (this.db.prepare(`SELECT COUNT(*) AS n FROM "${t.name}"`).get() as { n: number }).n,
				columns: (this.db.prepare(`PRAGMA table_info("${t.name}")`).all() as Array<{ name: string; type: string }>).map(c => `${c.name} ${c.type}`.trim()),
			}));
	}

	/**
	 * Run one read-only SELECT on a separate read-only connection. Credential
	 * tables are refused; at most `maxRows` rows come back.
	 */
	readonlyQuery(sql: string, maxRows: number): { columns: string[]; rows: unknown[][]; truncated: boolean } {
		const trimmed = sql.trim().replace(/;\s*$/, '');
		if (!/^(select|with)\b/i.test(trimmed)) throw new Error('Only a single SELECT (or WITH … SELECT) statement is allowed.');
		if (PRIVATE_TABLES.test(trimmed)) throw new Error('That table holds credentials and is not queryable.');
		if (/\b(attach|detach|pragma|load_extension)\b/i.test(trimmed)) throw new Error('ATTACH, PRAGMA and extensions are not allowed.');
		if (!this.ro) {
			this.ro = new Database(this.dbPath, { readonly: true, fileMustExist: true });
			this.ro.pragma('busy_timeout = 5000');
			this.ro.function('gunzip_json', { deterministic: true }, (blob: unknown) =>
				Buffer.isBuffer(blob) ? gunzipSync(blob).toString('utf8') : null
			);
		}
		const stmt = this.ro.prepare(trimmed);
		if (!stmt.reader || !stmt.readonly) throw new Error('Only read-only queries that return rows are allowed.');
		stmt.raw(true);
		const columns = stmt.columns().map(c => c.name);
		const rows: unknown[][] = [];
		let truncated = false;
		for (const row of stmt.iterate() as IterableIterator<unknown[]>) {
			if (rows.length >= maxRows) {
				truncated = true;
				break;
			}
			rows.push(row.map(v => (Buffer.isBuffer(v) ? `<${v.length} bytes gzip — wrap in gunzip_json()>` : v)));
		}
		return { columns, rows, truncated };
	}

	// ---- sync state --------------------------------------------------------

	getSyncState(): { last_sync_at: string | null; oldest_date: string | null; newest_date: string | null; last_error: string | null } {
		return this.db.prepare('SELECT last_sync_at, oldest_date, newest_date, last_error FROM garmin_sync_state WHERE id = 1').get() as {
			last_sync_at: string | null;
			oldest_date: string | null;
			newest_date: string | null;
			last_error: string | null;
		};
	}

	recordSync(oldest: string, newest: string): void {
		this.db.prepare(`
			UPDATE garmin_sync_state
			SET last_sync_at = CURRENT_TIMESTAMP,
				oldest_date = CASE WHEN oldest_date IS NULL OR ? < oldest_date THEN ? ELSE oldest_date END,
				newest_date = CASE WHEN newest_date IS NULL OR ? > newest_date THEN ? ELSE newest_date END,
				last_error = NULL
			WHERE id = 1
		`).run(oldest, oldest, newest, newest);
	}

	recordSyncError(message: string): void {
		this.db.prepare('UPDATE garmin_sync_state SET last_error = ? WHERE id = 1').run(message.slice(0, 500));
	}

	close(): void {
		this.ro?.close();
		this.db.close();
	}
}

// ----------------------------------------------------------------- sync ---

interface DailyResponse {
	date: string;
	normalised: Record<string, unknown>;
	intraday?: Record<string, Array<[number, number]>>;
	raw: Record<string, unknown>;
	errors: Record<string, string>;
}

interface ActivitiesResponse {
	activities: Array<{ normalised: Record<string, unknown>; raw: unknown }>;
}

interface ProfileResponse {
	snapshots: Record<string, unknown>;
	errors: Record<string, string>;
}

export interface GarminSyncResult {
	type: 'skip' | 'quick' | 'initial' | 'range';
	days?: number;
	skipped_days?: number;
	activities?: number;
	details?: number;
	profile?: boolean;
}

export interface BackfillStatus {
	running: boolean;
	phase?: 'days' | 'activities' | 'details' | 'profile' | 'waiting';
	total: number;
	done: number;
	already_complete?: number;
	details_total?: number;
	details_done?: number;
	from?: string;
	to?: string;
	waiting_until?: string;
	error?: string;
	finished_at?: string;
}

interface RangeOptions {
	/** Delay between days (ms). */
	paceMs?: number;
	/** Re-fetch days even if every source is already stored. */
	refresh?: boolean;
	/** Max activity details to fetch this run (default: all pending). */
	detailLimit?: number;
	/** Wait out Garmin rate limits instead of failing (backfills). */
	patient?: boolean;
	onProgress?: (status: Partial<BackfillStatus>) => void;
}

/** Back-off schedule (minutes) when a backfill hits Garmin's rate limit. */
const RATE_LIMIT_WAITS_MS = (process.env.GARMIN_RATE_LIMIT_WAITS_MIN ?? '10,20,40')
	.split(',')
	.map(Number)
	.filter(m => Number.isFinite(m) && m > 0)
	.map(m => m * 60_000);
/** How many recent days are always re-pulled: today's totals and last night's sleep keep settling. */
const UNSETTLED_DAYS = 2;

export class GarminSync {
	private queue: Promise<unknown> = Promise.resolve();
	private backfill: BackfillStatus = { running: false, total: 0, done: 0 };

	constructor(
		private readonly bridge: GarminBridge,
		private readonly store: GarminStore
	) {}

	isConnected(): boolean {
		return this.store.getTokens() != null;
	}

	backfillStatus(): BackfillStatus {
		return { ...this.backfill };
	}

	/** Runs sync jobs one at a time so cron, tools and backfills never overlap. */
	private exclusive<T>(job: () => Promise<T>): Promise<T> {
		const run = this.queue.then(job, job);
		this.queue = run.catch(() => {});
		return run;
	}

	/** Bridge call that, in patient mode, sleeps through Garmin's rate limiting. */
	private async call<T>(path: string, body: unknown, timeoutMs: number, opts: RangeOptions): Promise<T> {
		for (let attempt = 0; ; attempt++) {
			try {
				return await this.bridge.call<T>(path, body, timeoutMs);
			} catch (err) {
				const limited = err instanceof GarminBridgeError && err.status === 429;
				if (!limited || !opts.patient || attempt >= RATE_LIMIT_WAITS_MS.length) throw err;
				const wait = RATE_LIMIT_WAITS_MS[attempt];
				console.warn(`[garmin] rate limited; waiting ${wait / 60_000} min before retrying`);
				opts.onProgress?.({ phase: 'waiting', waiting_until: new Date(Date.now() + wait).toISOString() });
				await sleep(wait);
				opts.onProgress?.({ waiting_until: undefined });
			}
		}
	}

	/**
	 * Pull everything for [start, end]: every daily source (skipping days already
	 * complete, except the last couple which keep settling), the activity list,
	 * per-activity detail for anything not yet fetched, and profile snapshots
	 * when they're more than a day old.
	 */
	syncRange(start: string, end: string, opts: RangeOptions = {}): Promise<GarminSyncResult> {
		return this.exclusive(async () => {
			try {
				const unsettledFrom = localDate(UNSETTLED_DAYS - 1);
				const all = dateRange(start, end);
				const incomplete = new Set(opts.refresh ? all : this.store.incompleteDays(start, end));
				const days = all.filter(d => incomplete.has(d) || d >= unsettledFrom).reverse(); // newest first
				opts.onProgress?.({ phase: 'days', total: days.length, done: 0, already_complete: all.length - days.length });

				for (const [i, day] of days.entries()) {
					if (i && opts.paceMs) await sleep(opts.paceMs);
					const res = await this.call<DailyResponse>('/daily', { date: day }, 180_000, opts);
					this.store.upsertDaily(res.normalised, res.raw, res.errors, res.intraday ?? {});
					opts.onProgress?.({ phase: 'days', done: i + 1 });
				}

				opts.onProgress?.({ phase: 'activities' });
				let activities = 0;
				// Activities endpoint pages internally; chunk long windows to keep requests modest.
				for (let chunkStart = start; chunkStart <= end; chunkStart = addDays(chunkStart, 90)) {
					const chunkEnd = addDays(chunkStart, 89) < end ? addDays(chunkStart, 89) : end;
					const res = await this.call<ActivitiesResponse>('/activities', { start: chunkStart, end: chunkEnd }, 120_000, opts);
					if (res.activities.length) this.store.upsertActivities(res.activities);
					activities += res.activities.length;
				}

				const pending = this.store.activitiesNeedingDetail(opts.detailLimit ?? 10_000);
				opts.onProgress?.({ phase: 'details', details_total: pending.length, details_done: 0 });
				for (const [i, a] of pending.entries()) {
					if (i && opts.paceMs) await sleep(opts.paceMs);
					const res = await this.call<ActivityDetailResponse>(
						'/activity/detail',
						{ activity_id: a.activity_id, type_key: a.type_key, has_sets: a.total_sets != null && a.total_sets > 0 },
						180_000,
						opts
					);
					this.store.upsertActivityDetail(res);
					opts.onProgress?.({ details_done: i + 1 });
				}

				let profile = false;
				const age = this.store.snapshotsAgeHours();
				if (age == null || age > 20) {
					opts.onProgress?.({ phase: 'profile' });
					const res = await this.call<ProfileResponse>('/profile', { today: localDate(0) }, 180_000, opts);
					this.store.upsertSnapshots(res.snapshots, res.errors);
					profile = true;
				}

				this.store.recordSync(start, end);
				return { type: 'range' as const, days: days.length, skipped_days: all.length - days.length, activities, details: pending.length, profile };
			} catch (err) {
				this.store.recordSyncError(err instanceof Error ? err.message : String(err));
				throw err;
			}
		});
	}

	/** Fetch (or re-fetch) one activity's detail now. */
	syncActivityDetail(activityId: number): Promise<void> {
		return this.exclusive(async () => {
			const a = this.store.getActivity(activityId);
			const res = await this.bridge.call<ActivityDetailResponse>(
				'/activity/detail',
				{ activity_id: activityId, type_key: a?.type_key ?? null, has_sets: typeof a?.total_sets === 'number' && a.total_sets > 0 },
				180_000
			);
			this.store.upsertActivityDetail(res);
		});
	}

	/**
	 * Hourly-safe refresh: skips if synced within the hour, otherwise re-pulls
	 * yesterday and today (yesterday's totals and last night's sleep settle
	 * after midnight) plus detail for up to 5 new activities. First run pulls
	 * two weeks.
	 */
	async smartSync(): Promise<GarminSyncResult> {
		if (!this.isConnected()) throw new GarminBridgeError(401, 'not_authenticated', 'Garmin is not connected');
		const state = this.store.getSyncState();
		const today = localDate(0);
		if (!state.last_sync_at) {
			const r = await this.syncRange(localDate(13), today, { paceMs: 500, detailLimit: 20 });
			return { ...r, type: 'initial' };
		}
		const minutesSince = (Date.now() - Date.parse(`${state.last_sync_at.replace(' ', 'T')}Z`)) / 60_000;
		if (minutesSince < 60) return { type: 'skip' };
		const r = await this.syncRange(localDate(1), today, { detailLimit: 5 });
		return { ...r, type: 'quick' };
	}

	/**
	 * Background historical pull, paced gently and patient with Garmin's rate
	 * limits. Days already fully stored are skipped unless `refresh` is set, so
	 * it is safe to re-run (it resumes where a stopped run left off).
	 */
	startBackfill(days: number, refresh = false): BackfillStatus {
		if (this.backfill.running) return this.backfillStatus();
		const from = localDate(days - 1);
		const to = localDate(0);
		this.backfill = { running: true, phase: 'days', total: days, done: 0, from, to };
		this.syncRange(from, to, {
			paceMs: 1500,
			refresh,
			patient: true,
			onProgress: s => {
				this.backfill = { ...this.backfill, ...s };
			},
		})
			.then(() => {
				this.backfill = { ...this.backfill, running: false, phase: undefined, waiting_until: undefined, finished_at: new Date().toISOString() };
				console.log('[garmin] backfill complete', this.backfill);
			})
			.catch(err => {
				const message = err instanceof Error ? err.message : String(err);
				this.backfill = { ...this.backfill, running: false, waiting_until: undefined, error: message, finished_at: new Date().toISOString() };
				console.error('[garmin] backfill stopped:', message);
			});
		return this.backfillStatus();
	}
}
