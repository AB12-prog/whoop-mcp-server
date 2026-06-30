import Database from 'better-sqlite3';
import { encrypt, decrypt, isEncrypted } from './crypto.js';
import type {
	WhoopTokens,
	WhoopUser,
	WhoopBodyMeasurement,
	WhoopCycle,
	WhoopRecovery,
	WhoopSleep,
	WhoopWorkout,
	DbCycle,
	DbRecovery,
	DbSleep,
	DbWorkout,
	DbProfile,
	DbBodyMeasurement,
} from './types.js';

interface TokenRow {
	id: number;
	access_token: string;
	refresh_token: string;
	expires_at: number;
	updated_at: string;
}

interface SyncStateRow {
	id: number;
	last_sync_at: string | null;
	oldest_synced_date: string | null;
	newest_synced_date: string | null;
}

interface RecoveryTrendRow {
	date: string;
	recovery_score: number;
	hrv: number;
	rhr: number;
}

interface SleepTrendRow {
	date: string;
	total_sleep_hours: number;
	performance: number;
	efficiency: number;
}

interface StrainTrendRow {
	date: string;
	strain: number;
	calories: number;
}

export class WhoopDatabase {
	private db: Database.Database;

	constructor(dbPath = './whoop.db') {
		this.db = new Database(dbPath);
		this.db.pragma('journal_mode = WAL');
		this.initSchema();
		this.migrateColumns();
	}

	// Adds any columns introduced after a database was first created, so an
	// existing volume upgrades in place instead of being wiped. ALTER TABLE ADD
	// COLUMN is a cheap metadata-only operation in SQLite.
	private migrateColumns(): void {
		const desired: Record<string, Record<string, string>> = {
			cycles: { timezone_offset: 'TEXT' },
			recovery: { updated_at: 'TEXT', user_calibrating: 'INTEGER' },
			sleep: {
				cycle_id: 'INTEGER', created_at: 'TEXT', updated_at: 'TEXT', timezone_offset: 'TEXT',
				total_no_data_milli: 'INTEGER', sleep_cycle_count: 'INTEGER', disturbance_count: 'INTEGER',
				sleep_needed_nap_milli: 'INTEGER',
			},
			workouts: {
				v1_id: 'INTEGER', sport_name: 'TEXT', created_at: 'TEXT', updated_at: 'TEXT', timezone_offset: 'TEXT',
				percent_recorded: 'REAL', distance_meter: 'REAL', altitude_gain_meter: 'REAL', altitude_change_meter: 'REAL',
			},
		};

		for (const [table, columns] of Object.entries(desired)) {
			const existing = new Set(
				(this.db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map(c => c.name)
			);
			for (const [name, type] of Object.entries(columns)) {
				if (!existing.has(name)) {
					this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
				}
			}
		}
	}

	private initSchema(): void {
		this.db.exec(`
			CREATE TABLE IF NOT EXISTS tokens (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				access_token TEXT NOT NULL,
				refresh_token TEXT NOT NULL,
				expires_at INTEGER NOT NULL,
				updated_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE TABLE IF NOT EXISTS sync_state (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				last_sync_at TEXT,
				oldest_synced_date TEXT,
				newest_synced_date TEXT
			);

			CREATE TABLE IF NOT EXISTS cycles (
				id INTEGER PRIMARY KEY,
				user_id INTEGER NOT NULL,
				start_time TEXT NOT NULL,
				end_time TEXT,
				timezone_offset TEXT,
				score_state TEXT NOT NULL,
				strain REAL,
				kilojoule REAL,
				avg_hr INTEGER,
				max_hr INTEGER,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE TABLE IF NOT EXISTS recovery (
				id INTEGER PRIMARY KEY,
				user_id INTEGER NOT NULL,
				sleep_id TEXT,
				created_at TEXT NOT NULL,
				updated_at TEXT,
				score_state TEXT NOT NULL,
				user_calibrating INTEGER,
				recovery_score INTEGER,
				resting_hr INTEGER,
				hrv_rmssd REAL,
				spo2 REAL,
				skin_temp REAL,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE TABLE IF NOT EXISTS sleep (
				id TEXT PRIMARY KEY,
				user_id INTEGER NOT NULL,
				cycle_id INTEGER,
				created_at TEXT,
				updated_at TEXT,
				timezone_offset TEXT,
				start_time TEXT NOT NULL,
				end_time TEXT NOT NULL,
				is_nap INTEGER NOT NULL DEFAULT 0,
				score_state TEXT NOT NULL,
				total_in_bed_milli INTEGER,
				total_awake_milli INTEGER,
				total_no_data_milli INTEGER,
				total_light_milli INTEGER,
				total_deep_milli INTEGER,
				total_rem_milli INTEGER,
				sleep_cycle_count INTEGER,
				disturbance_count INTEGER,
				sleep_performance REAL,
				sleep_efficiency REAL,
				sleep_consistency REAL,
				respiratory_rate REAL,
				sleep_needed_baseline_milli INTEGER,
				sleep_needed_debt_milli INTEGER,
				sleep_needed_strain_milli INTEGER,
				sleep_needed_nap_milli INTEGER,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE TABLE IF NOT EXISTS workouts (
				id TEXT PRIMARY KEY,
				v1_id INTEGER,
				user_id INTEGER NOT NULL,
				sport_id INTEGER NOT NULL,
				sport_name TEXT,
				created_at TEXT,
				updated_at TEXT,
				timezone_offset TEXT,
				start_time TEXT NOT NULL,
				end_time TEXT NOT NULL,
				score_state TEXT NOT NULL,
				strain REAL,
				avg_hr INTEGER,
				max_hr INTEGER,
				kilojoule REAL,
				percent_recorded REAL,
				distance_meter REAL,
				altitude_gain_meter REAL,
				altitude_change_meter REAL,
				zone_zero_milli INTEGER,
				zone_one_milli INTEGER,
				zone_two_milli INTEGER,
				zone_three_milli INTEGER,
				zone_four_milli INTEGER,
				zone_five_milli INTEGER,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE TABLE IF NOT EXISTS profile (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				user_id INTEGER,
				email TEXT,
				first_name TEXT,
				last_name TEXT,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE TABLE IF NOT EXISTS body_measurement (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				height_meter REAL,
				weight_kilogram REAL,
				max_heart_rate INTEGER,
				synced_at TEXT DEFAULT CURRENT_TIMESTAMP
			);

			CREATE INDEX IF NOT EXISTS idx_cycles_start ON cycles(start_time);
			CREATE INDEX IF NOT EXISTS idx_recovery_created ON recovery(created_at);
			CREATE INDEX IF NOT EXISTS idx_sleep_start ON sleep(start_time);
			CREATE INDEX IF NOT EXISTS idx_workouts_start ON workouts(start_time);

			INSERT OR IGNORE INTO sync_state (id) VALUES (1);
		`);
	}

	saveTokens(tokens: WhoopTokens): void {
		const encryptedAccess = encrypt(tokens.access_token);
		const encryptedRefresh = encrypt(tokens.refresh_token);

		this.db.prepare(`
			INSERT OR REPLACE INTO tokens (id, access_token, refresh_token, expires_at, updated_at)
			VALUES (1, ?, ?, ?, CURRENT_TIMESTAMP)
		`).run(encryptedAccess, encryptedRefresh, tokens.expires_at);
	}

	getTokens(): WhoopTokens | null {
		const row = this.db.prepare('SELECT * FROM tokens WHERE id = 1').get() as TokenRow | undefined;
		if (!row) return null;

		const accessToken = isEncrypted(row.access_token)
			? decrypt(row.access_token)
			: row.access_token;

		const refreshToken = isEncrypted(row.refresh_token)
			? decrypt(row.refresh_token)
			: row.refresh_token;

		return {
			access_token: accessToken,
			refresh_token: refreshToken,
			expires_at: row.expires_at,
		};
	}

	getSyncState(): { lastSyncAt: string | null; oldestDate: string | null; newestDate: string | null } {
		const row = this.db.prepare('SELECT * FROM sync_state WHERE id = 1').get() as SyncStateRow | undefined;
		return {
			lastSyncAt: row?.last_sync_at ?? null,
			oldestDate: row?.oldest_synced_date ?? null,
			newestDate: row?.newest_synced_date ?? null,
		};
	}

	updateSyncState(oldestDate: string, newestDate: string): void {
		this.db.prepare(`
			UPDATE sync_state
			SET last_sync_at = CURRENT_TIMESTAMP,
				oldest_synced_date = COALESCE(
					CASE WHEN oldest_synced_date IS NULL OR ? < oldest_synced_date THEN ? ELSE oldest_synced_date END,
					?
				),
				newest_synced_date = COALESCE(
					CASE WHEN newest_synced_date IS NULL OR ? > newest_synced_date THEN ? ELSE newest_synced_date END,
					?
				)
			WHERE id = 1
		`).run(oldestDate, oldestDate, oldestDate, newestDate, newestDate, newestDate);
	}

	upsertCycles(cycles: WhoopCycle[]): void {
		const stmt = this.db.prepare(`
			INSERT OR REPLACE INTO cycles (id, user_id, start_time, end_time, timezone_offset, score_state, strain, kilojoule, avg_hr, max_hr, synced_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		`);

		const insertMany = this.db.transaction((items: WhoopCycle[]) => {
			for (const c of items) {
				stmt.run(
					c.id,
					c.user_id,
					c.start,
					c.end,
					c.timezone_offset ?? null,
					c.score_state,
					c.score?.strain ?? null,
					c.score?.kilojoule ?? null,
					c.score?.average_heart_rate ?? null,
					c.score?.max_heart_rate ?? null
				);
			}
		});

		insertMany(cycles);
	}

	upsertRecoveries(recoveries: WhoopRecovery[]): void {
		const stmt = this.db.prepare(`
			INSERT OR REPLACE INTO recovery (id, user_id, sleep_id, created_at, updated_at, score_state, user_calibrating, recovery_score, resting_hr, hrv_rmssd, spo2, skin_temp, synced_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		`);

		const insertMany = this.db.transaction((items: WhoopRecovery[]) => {
			for (const r of items) {
				stmt.run(
					r.cycle_id,
					r.user_id,
					r.sleep_id,
					r.created_at,
					r.updated_at ?? null,
					r.score_state,
					r.score ? (r.score.user_calibrating ? 1 : 0) : null,
					r.score?.recovery_score ?? null,
					r.score?.resting_heart_rate ?? null,
					r.score?.hrv_rmssd_milli ?? null,
					r.score?.spo2_percentage ?? null,
					r.score?.skin_temp_celsius ?? null
				);
			}
		});

		insertMany(recoveries);
	}

	upsertSleeps(sleeps: WhoopSleep[]): void {
		const stmt = this.db.prepare(`
			INSERT OR REPLACE INTO sleep (
				id, user_id, created_at, updated_at, timezone_offset, start_time, end_time, is_nap, score_state,
				total_in_bed_milli, total_awake_milli, total_no_data_milli, total_light_milli, total_deep_milli, total_rem_milli,
				sleep_cycle_count, disturbance_count,
				sleep_performance, sleep_efficiency, sleep_consistency, respiratory_rate,
				sleep_needed_baseline_milli, sleep_needed_debt_milli, sleep_needed_strain_milli, sleep_needed_nap_milli, synced_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		`);

		const insertMany = this.db.transaction((items: WhoopSleep[]) => {
			for (const s of items) {
				const ss = s.score?.stage_summary;
				const sn = s.score?.sleep_needed;
				stmt.run(
					s.id,
					s.user_id,
					s.created_at ?? null,
					s.updated_at ?? null,
					s.timezone_offset ?? null,
					s.start,
					s.end,
					s.nap ? 1 : 0,
					s.score_state,
					ss?.total_in_bed_time_milli ?? null,
					ss?.total_awake_time_milli ?? null,
					ss?.total_no_data_time_milli ?? null,
					ss?.total_light_sleep_time_milli ?? null,
					ss?.total_slow_wave_sleep_time_milli ?? null,
					ss?.total_rem_sleep_time_milli ?? null,
					ss?.sleep_cycle_count ?? null,
					ss?.disturbance_count ?? null,
					s.score?.sleep_performance_percentage ?? null,
					s.score?.sleep_efficiency_percentage ?? null,
					s.score?.sleep_consistency_percentage ?? null,
					s.score?.respiratory_rate ?? null,
					sn?.baseline_milli ?? null,
					sn?.need_from_sleep_debt_milli ?? null,
					sn?.need_from_recent_strain_milli ?? null,
					sn?.need_from_recent_nap_milli ?? null
				);
			}
		});

		insertMany(sleeps);
	}

	upsertWorkouts(workouts: WhoopWorkout[]): void {
		const stmt = this.db.prepare(`
			INSERT OR REPLACE INTO workouts (
				id, v1_id, user_id, sport_id, sport_name, created_at, updated_at, timezone_offset, start_time, end_time, score_state,
				strain, avg_hr, max_hr, kilojoule, percent_recorded, distance_meter, altitude_gain_meter, altitude_change_meter,
				zone_zero_milli, zone_one_milli, zone_two_milli, zone_three_milli, zone_four_milli, zone_five_milli,
				synced_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		`);

		const insertMany = this.db.transaction((items: WhoopWorkout[]) => {
			for (const w of items) {
				// v2 returns zone_durations (plural); fall back to the singular key just in case.
				const zones = w.score?.zone_durations ?? w.score?.zone_duration;
				stmt.run(
					w.id,
					w.v1_id ?? null,
					w.user_id,
					w.sport_id,
					w.sport_name ?? null,
					w.created_at ?? null,
					w.updated_at ?? null,
					w.timezone_offset ?? null,
					w.start,
					w.end,
					w.score_state,
					w.score?.strain ?? null,
					w.score?.average_heart_rate ?? null,
					w.score?.max_heart_rate ?? null,
					w.score?.kilojoule ?? null,
					w.score?.percent_recorded ?? null,
					w.score?.distance_meter ?? null,
					w.score?.altitude_gain_meter ?? null,
					w.score?.altitude_change_meter ?? null,
					zones?.zone_zero_milli ?? null,
					zones?.zone_one_milli ?? null,
					zones?.zone_two_milli ?? null,
					zones?.zone_three_milli ?? null,
					zones?.zone_four_milli ?? null,
					zones?.zone_five_milli ?? null
				);
			}
		});

		insertMany(workouts);
	}

	saveProfile(user: WhoopUser): void {
		this.db.prepare(`
			INSERT OR REPLACE INTO profile (id, user_id, email, first_name, last_name, synced_at)
			VALUES (1, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		`).run(user.user_id, user.email, user.first_name, user.last_name);
	}

	getProfile(): DbProfile | null {
		return this.db.prepare('SELECT user_id, email, first_name, last_name, synced_at FROM profile WHERE id = 1').get() as DbProfile | undefined ?? null;
	}

	saveBodyMeasurement(body: WhoopBodyMeasurement): void {
		this.db.prepare(`
			INSERT OR REPLACE INTO body_measurement (id, height_meter, weight_kilogram, max_heart_rate, synced_at)
			VALUES (1, ?, ?, ?, CURRENT_TIMESTAMP)
		`).run(body.height_meter, body.weight_kilogram, body.max_heart_rate);
	}

	getBodyMeasurement(): DbBodyMeasurement | null {
		return this.db.prepare('SELECT height_meter, weight_kilogram, max_heart_rate, synced_at FROM body_measurement WHERE id = 1').get() as DbBodyMeasurement | undefined ?? null;
	}

	getLatestCycle(): DbCycle | null {
		return this.db.prepare('SELECT * FROM cycles ORDER BY start_time DESC LIMIT 1').get() as DbCycle | undefined ?? null;
	}

	getLatestRecovery(): DbRecovery | null {
		return this.db.prepare('SELECT * FROM recovery ORDER BY created_at DESC LIMIT 1').get() as DbRecovery | undefined ?? null;
	}

	getLatestSleep(): DbSleep | null {
		return this.db.prepare('SELECT * FROM sleep WHERE is_nap = 0 ORDER BY start_time DESC LIMIT 1').get() as DbSleep | undefined ?? null;
	}

	getCyclesByDateRange(startDate: string, endDate: string): DbCycle[] {
		return this.db.prepare(`
			SELECT * FROM cycles WHERE start_time >= ? AND start_time <= ? ORDER BY start_time DESC
		`).all(startDate, endDate) as DbCycle[];
	}

	getRecoveriesByDateRange(startDate: string, endDate: string): DbRecovery[] {
		return this.db.prepare(`
			SELECT * FROM recovery WHERE created_at >= ? AND created_at <= ? ORDER BY created_at DESC
		`).all(startDate, endDate) as DbRecovery[];
	}

	getSleepsByDateRange(startDate: string, endDate: string, includeNaps = false): DbSleep[] {
		const query = includeNaps
			? 'SELECT * FROM sleep WHERE start_time >= ? AND start_time <= ? ORDER BY start_time DESC'
			: 'SELECT * FROM sleep WHERE start_time >= ? AND start_time <= ? AND is_nap = 0 ORDER BY start_time DESC';
		return this.db.prepare(query).all(startDate, endDate) as DbSleep[];
	}

	getWorkoutsByDateRange(startDate: string, endDate: string): DbWorkout[] {
		return this.db.prepare(`
			SELECT * FROM workouts WHERE start_time >= ? AND start_time <= ? ORDER BY start_time DESC
		`).all(startDate, endDate) as DbWorkout[];
	}

	getRecoveryTrends(days: number): RecoveryTrendRow[] {
		return this.db.prepare(`
			SELECT DATE(created_at) as date, recovery_score, hrv_rmssd as hrv, resting_hr as rhr
			FROM recovery
			WHERE recovery_score IS NOT NULL AND created_at >= DATE('now', '-' || ? || ' days')
			ORDER BY created_at DESC
		`).all(days) as RecoveryTrendRow[];
	}

	getSleepTrends(days: number): SleepTrendRow[] {
		return this.db.prepare(`
			SELECT DATE(start_time) as date,
				ROUND((total_in_bed_milli - total_awake_milli) / 3600000.0, 2) as total_sleep_hours,
				sleep_performance as performance, sleep_efficiency as efficiency
			FROM sleep
			WHERE is_nap = 0 AND sleep_performance IS NOT NULL AND start_time >= DATE('now', '-' || ? || ' days')
			ORDER BY start_time DESC
		`).all(days) as SleepTrendRow[];
	}

	getStrainTrends(days: number): StrainTrendRow[] {
		return this.db.prepare(`
			SELECT DATE(start_time) as date, strain, ROUND(kilojoule / 4.184, 0) as calories
			FROM cycles
			WHERE strain IS NOT NULL AND start_time >= DATE('now', '-' || ? || ' days')
			ORDER BY start_time DESC
		`).all(days) as StrainTrendRow[];
	}

	close(): void {
		this.db.close();
	}
}
