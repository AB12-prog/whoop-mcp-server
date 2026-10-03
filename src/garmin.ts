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
			env: { ...process.env, BRIDGE_SECRET: this.secret, PYTHONUNBUFFERED: '1' },
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

// Normalised daily columns. Keep in step with normalise_daily() in bridge.py.
const DAILY_COLUMNS: Record<string, 'INTEGER' | 'REAL' | 'TEXT'> = {
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
};

const ACTIVITY_COLUMNS: Record<string, 'INTEGER' | 'REAL' | 'TEXT'> = {
	name: 'TEXT', type_key: 'TEXT', start_local: 'TEXT', start_gmt: 'TEXT',
	duration_s: 'REAL', moving_s: 'REAL', distance_m: 'REAL', avg_hr: 'REAL', max_hr: 'REAL', kcal: 'REAL',
	aerobic_te: 'REAL', anaerobic_te: 'REAL', training_load: 'REAL', avg_speed: 'REAL', elevation_gain: 'REAL',
	z1_s: 'REAL', z2_s: 'REAL', z3_s: 'REAL', z4_s: 'REAL', z5_s: 'REAL',
};

export const RAW_SOURCES = ['summary', 'sleep', 'hrv', 'readiness', 'training_status'] as const;
export type RawSource = (typeof RAW_SOURCES)[number];

export type GarminDailyRow = { date: string; synced_at: string; errors: string | null } & Record<string, unknown>;
export type GarminActivityRow = { activity_id: number; synced_at: string } & Record<string, unknown>;

function cell(value: unknown): string | number | null {
	if (value === null || value === undefined) return null;
	if (typeof value === 'number') return Number.isFinite(value) ? value : null;
	if (typeof value === 'boolean') return value ? 1 : 0;
	return String(value);
}

export class GarminStore {
	private readonly db: Database.Database;

	constructor(dbPath: string) {
		this.db = new Database(dbPath);
		this.db.pragma('journal_mode = WAL');
		this.db.pragma('busy_timeout = 5000');

		const dailyCols = Object.entries(DAILY_COLUMNS).map(([n, t]) => `${n} ${t}`).join(',\n');
		const actCols = Object.entries(ACTIVITY_COLUMNS).map(([n, t]) => `${n} ${t}`).join(',\n');
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
				${dailyCols},
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
			CREATE TABLE IF NOT EXISTS garmin_activities (
				activity_id INTEGER PRIMARY KEY,
				${actCols},
				raw TEXT,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);
			CREATE INDEX IF NOT EXISTS idx_garmin_activities_start ON garmin_activities(start_local);
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

	upsertDaily(norm: Record<string, unknown>, raw: Record<string, unknown>, errors: Record<string, string>): void {
		const cols = Object.keys(DAILY_COLUMNS);
		const stmt = this.db.prepare(`
			INSERT OR REPLACE INTO garmin_daily (date, ${cols.join(', ')}, errors, synced_at)
			VALUES (?, ${cols.map(() => '?').join(', ')}, ?, CURRENT_TIMESTAMP)
		`);
		const rawStmt = this.db.prepare(`
			INSERT OR REPLACE INTO garmin_daily_raw (date, source, json, synced_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		`);
		const date = String(norm.date);
		this.db.transaction(() => {
			stmt.run(date, ...cols.map(c => cell(norm[c])), Object.keys(errors).length ? JSON.stringify(errors) : null);
			for (const source of RAW_SOURCES) {
				rawStmt.run(date, source, raw[source] == null ? null : JSON.stringify(raw[source]));
			}
		})();
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

	getRaw(date: string, source: RawSource): unknown {
		const row = this.db.prepare('SELECT json FROM garmin_daily_raw WHERE date = ? AND source = ?').get(date, source) as { json: string | null } | undefined;
		if (!row) return undefined;
		return row.json == null ? null : JSON.parse(row.json);
	}

	// ---- activities --------------------------------------------------------

	upsertActivities(items: Array<{ normalised: Record<string, unknown>; raw: unknown }>): void {
		const cols = Object.keys(ACTIVITY_COLUMNS);
		const stmt = this.db.prepare(`
			INSERT OR REPLACE INTO garmin_activities (activity_id, ${cols.join(', ')}, raw, synced_at)
			VALUES (?, ${cols.map(() => '?').join(', ')}, ?, CURRENT_TIMESTAMP)
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
		this.db.close();
	}
}

// ----------------------------------------------------------------- sync ---

interface DailyResponse {
	date: string;
	normalised: Record<string, unknown>;
	raw: Record<string, unknown>;
	errors: Record<string, string>;
}

interface ActivitiesResponse {
	activities: Array<{ normalised: Record<string, unknown>; raw: unknown }>;
}

export interface GarminSyncResult {
	type: 'skip' | 'quick' | 'initial' | 'range';
	days?: number;
	activities?: number;
}

export interface BackfillStatus {
	running: boolean;
	total: number;
	done: number;
	from?: string;
	to?: string;
	error?: string;
	finished_at?: string;
}

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

	/** Pull daily metrics for [start, end] plus activities in that window. */
	syncRange(start: string, end: string, paceMs = 0, onDay?: () => void): Promise<GarminSyncResult> {
		return this.exclusive(async () => {
			try {
				const days = dateRange(start, end);
				for (const [i, day] of days.entries()) {
					if (i && paceMs) await sleep(paceMs);
					const res = await this.bridge.call<DailyResponse>('/daily', { date: day });
					this.store.upsertDaily(res.normalised, res.raw, res.errors);
					onDay?.();
				}
				let activities = 0;
				// Activities endpoint pages internally; chunk long windows to keep requests modest.
				for (let chunkStart = start; chunkStart <= end; chunkStart = addDays(chunkStart, 90)) {
					const chunkEnd = addDays(chunkStart, 89) < end ? addDays(chunkStart, 89) : end;
					const res = await this.bridge.call<ActivitiesResponse>('/activities', { start: chunkStart, end: chunkEnd }, 120_000);
					if (res.activities.length) this.store.upsertActivities(res.activities);
					activities += res.activities.length;
				}
				this.store.recordSync(start, end);
				return { type: 'range' as const, days: days.length, activities };
			} catch (err) {
				this.store.recordSyncError(err instanceof Error ? err.message : String(err));
				throw err;
			}
		});
	}

	/**
	 * Hourly-safe refresh: skips if synced within the hour, otherwise re-pulls
	 * yesterday and today (yesterday's totals and last night's sleep settle
	 * after midnight). First run pulls two weeks.
	 */
	async smartSync(): Promise<GarminSyncResult> {
		if (!this.isConnected()) throw new GarminBridgeError(401, 'not_authenticated', 'Garmin is not connected');
		const state = this.store.getSyncState();
		const today = localDate(0);
		if (!state.last_sync_at) {
			const r = await this.syncRange(localDate(13), today, 500);
			return { ...r, type: 'initial' };
		}
		const minutesSince = (Date.now() - Date.parse(`${state.last_sync_at.replace(' ', 'T')}Z`)) / 60_000;
		if (minutesSince < 60) return { type: 'skip' };
		const r = await this.syncRange(localDate(1), today);
		return { ...r, type: 'quick' };
	}

	/** Background historical pull, paced gently to avoid Garmin rate limits. */
	startBackfill(days: number): BackfillStatus {
		if (this.backfill.running) return this.backfillStatus();
		const from = localDate(days - 1);
		const to = localDate(0);
		this.backfill = { running: true, total: days, done: 0, from, to };
		this.syncRange(from, to, 1500, () => {
			this.backfill.done += 1;
		})
			.then(() => {
				this.backfill = { ...this.backfill, running: false, finished_at: new Date().toISOString() };
				console.log('[garmin] backfill complete', this.backfill);
			})
			.catch(err => {
				const message = err instanceof Error ? err.message : String(err);
				this.backfill = { ...this.backfill, running: false, error: message, finished_at: new Date().toISOString() };
				console.error('[garmin] backfill stopped:', message);
			});
		return this.backfillStatus();
	}
}
