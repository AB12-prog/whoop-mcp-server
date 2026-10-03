// src/garmin-tools.ts — MCP tool definitions and handlers for Garmin data.

import {
	ACTIVITY_SOURCES,
	DAILY_SOURCES,
	GarminBridgeError,
	GarminStore,
	GarminSync,
	INTRADAY_METRICS,
	localDate,
	type BackfillStatus,
	type GarminActivityRow,
	type GarminDailyRow,
} from './garmin.js';
import {
	INTRADAY_AGG,
	SLEEP_STAGE_NAMES,
	bucketIntraday,
	fmtDuration,
	fmtPace,
	localDateTime,
	localTime,
	parseActivitySeries,
	resampleSeries,
	seriesInsights,
} from './garmin-analysis.js';

type ToolResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean };

const text = (t: string, isError = false): ToolResult => ({ content: [{ type: 'text', text: t }], ...(isError ? { isError } : {}) });

/** Keep any single tool response to a size a model can actually read. */
const MAX_OUTPUT_CHARS = 120_000;
function capped(t: string): ToolResult {
	if (t.length <= MAX_OUTPUT_CHARS) return text(t);
	return text(`${t.slice(0, MAX_OUTPUT_CHARS)}\n\n…[truncated at ${MAX_OUTPUT_CHARS} characters — narrow the request]`);
}

function clampInt(value: unknown, fallback: number, min: number, max: number): number {
	const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
	if (!Number.isFinite(n)) return fallback;
	return Math.min(Math.max(Math.trunc(n), min), max);
}

const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const fmtNum = (v: unknown, digits = 0): string => (isNum(v) ? v.toFixed(digits) : '—');

function fmtHours(seconds: unknown): string {
	if (!isNum(seconds)) return '—';
	const h = Math.floor(seconds / 3600);
	const m = Math.round((seconds % 3600) / 60);
	return `${h}h ${String(m).padStart(2, '0')}m`;
}

function avg(rows: GarminDailyRow[], key: string): number | null {
	const vals = rows.map(r => r[key]).filter(isNum);
	return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
}

const pretty = (s: unknown): string => (typeof s === 'string' ? s.replace(/_\d+$/, '').replace(/_/g, ' ').toLowerCase() : '—');
const isDate = (s: string) => /^\d{4}-\d{2}-\d{2}$/.test(s);
const isRun = (a: GarminActivityRow) => /run/i.test(String(a.type_key ?? ''));

export const garminToolDefs = [
	{
		name: 'garmin_today',
		description:
			"Today's Garmin snapshot (Brisbane date): training readiness, last night's sleep (score, stages), overnight HRV vs baseline, resting HR, Body Battery, stress, steps, training status/load, and today's activities. Use this for any 'how am I today / should I train' question.",
		inputSchema: { type: 'object', properties: {}, required: [] },
	},
	{
		name: 'garmin_trends',
		description: 'Day-by-day Garmin trends with averages: training readiness, overnight HRV, resting HR, sleep duration and score, Body Battery, stress, steps.',
		inputSchema: {
			type: 'object',
			properties: { days: { type: 'number', description: 'Days to include, ending today (default 14, max 730).' } },
			required: [],
		},
	},
	{
		name: 'garmin_activities',
		description:
			'Garmin-recorded activities (runs, strength, rides, etc.) with id, duration, distance, pace, HR, cadence, training effect and load. Use the id with garmin_activity_detail for splits, zones and the time series.',
		inputSchema: {
			type: 'object',
			properties: { days: { type: 'number', description: 'Days back from today (default 14, max 730).' } },
			required: [],
		},
	},
	{
		name: 'garmin_activity_detail',
		description:
			'Deep dive on one activity: full summary (pace, GAP, cadence, stride, ground contact, vertical oscillation, power, temperature, training effect), weather, HR-zone time with boundaries, per-lap/km splits, strength sets (exercise, reps, kg), and analysis of the recorded time series (first vs second half, aerobic decoupling, HR drift, pace steadiness). Optionally include the downsampled series. Defaults to the most recent activity.',
		inputSchema: {
			type: 'object',
			properties: {
				activity_id: { type: 'number', description: 'Garmin activity id (from garmin_activities).' },
				date: { type: 'string', description: 'YYYY-MM-DD: use the latest activity on this date instead of an id.' },
				series: { type: 'boolean', description: 'Include the time series table (default false).' },
				resolution_s: { type: 'number', description: 'Series bucket size in seconds (default 60, min 5).' },
				refresh: { type: 'boolean', description: 'Re-fetch the detail from Garmin even if stored.' },
			},
			required: [],
		},
	},
	{
		name: 'garmin_intraday',
		description:
			'Intraday series for a day (or range): heart rate, stress, Body Battery, respiration, SpO2, steps, overnight HRV readings and sleep stages, bucketed in local (Brisbane) time. Omit metric for a combined table of hr/stress/body_battery/respiration/steps.',
		inputSchema: {
			type: 'object',
			properties: {
				date: { type: 'string', description: 'YYYY-MM-DD (default today).' },
				end_date: { type: 'string', description: 'Optional YYYY-MM-DD to cover a range (max 14 days).' },
				metric: { type: 'string', enum: [...INTRADAY_METRICS] },
				resolution_min: { type: 'number', description: 'Bucket size in minutes (default 15; 1–240).' },
			},
			required: [],
		},
	},
	{
		name: 'garmin_profile',
		description:
			'Account-level Garmin data: HR zones and the max/resting/threshold HR they use, race predictions (and history), lactate threshold, VO2 max, endurance and hill score, running tolerance, personal records, body composition, devices, goals. No kind = curated summary; kind = that dataset as JSON.',
		inputSchema: {
			type: 'object',
			properties: {
				kind: {
					type: 'string',
					enum: [
						'user_settings', 'heart_rate_zones', 'personal_records', 'race_predictions', 'race_predictions_history',
						'lactate_threshold', 'lactate_threshold_history', 'endurance_score', 'hill_score', 'running_tolerance',
						'body_composition', 'devices', 'primary_device', 'goals', 'training_plans',
					],
				},
			},
			required: [],
		},
	},
	{
		name: 'garmin_records',
		description:
			'Full normalised Garmin rows as JSON for detailed analysis. type "daily" = one row per date (every metric column); type "activities" = one row per activity.',
		inputSchema: {
			type: 'object',
			properties: {
				type: { type: 'string', enum: ['daily', 'activities'] },
				days: { type: 'number', description: 'Days back from today (default 14, max 730).' },
				limit: { type: 'number', description: 'Max rows, most recent first (default 500, max 2000).' },
			},
			required: ['type'],
		},
	},
	{
		name: 'garmin_raw',
		description:
			"Garmin's raw JSON for one date + daily source, or one activity + activity source — for detail not in the normalised tables. Daily sources: " +
			DAILY_SOURCES.join(', ') +
			'. Activity sources: ' +
			ACTIVITY_SOURCES.join(', ') +
			' (prefer garmin_activity_detail for "details", which is large).',
		inputSchema: {
			type: 'object',
			properties: {
				date: { type: 'string', description: 'YYYY-MM-DD (Brisbane calendar date). Sleep is filed under the morning it ended.' },
				activity_id: { type: 'number', description: 'Use instead of date for an activity source.' },
				source: { type: 'string', enum: [...new Set<string>([...DAILY_SOURCES, ...ACTIVITY_SOURCES])] },
			},
			required: ['source'],
		},
	},
	{
		name: 'garmin_schema',
		description:
			'List the tables and columns in the Garmin/WHOOP database (with row counts) for writing garmin_query SQL. Call this before the first garmin_query.',
		inputSchema: { type: 'object', properties: {}, required: [] },
	},
	{
		name: 'garmin_query',
		description:
			'Run one read-only SQL SELECT against the health database (SQLite) for custom analysis — correlations, weekly rollups, comparisons across months, joins of sleep vs training, WHOOP vs Garmin. Key tables: garmin_daily (one row per date), garmin_activities, garmin_activity_laps, garmin_activity_sets, garmin_activity_zones, garmin_intraday (date, metric, ts epoch-ms UTC, value; metrics: ' +
			INTRADAY_METRICS.join(', ') +
			'), garmin_daily_raw (json, or gz → use gunzip_json(gz) with json_extract), garmin_snapshots. Local time: datetime(ts/1000, \'unixepoch\', \'+10 hours\'). Credential tables are blocked.',
		inputSchema: {
			type: 'object',
			properties: {
				sql: { type: 'string', description: 'A single SELECT / WITH … SELECT statement.' },
				limit: { type: 'number', description: 'Max rows returned (default 500, max 5000).' },
			},
			required: ['sql'],
		},
	},
	{
		name: 'garmin_sync',
		description:
			'Sync Garmin data. With no days: refresh yesterday and today (and show backfill progress). With days > 7: start a background historical backfill of everything (daily metrics + intraday, activities + their detail, profile) for that many days — resumable, skips days already complete unless refresh is true, waits out Garmin rate limits. Call again with no arguments to see progress.',
		inputSchema: {
			type: 'object',
			properties: {
				days: { type: 'number', description: 'Optional: backfill this many days (max 730).' },
				refresh: { type: 'boolean', description: 'With days: re-fetch days even if already stored.' },
			},
			required: [],
		},
	},
	{
		name: 'garmin_auth_url',
		description: 'Get the link to (re)connect Garmin if the session has expired.',
		inputSchema: { type: 'object', properties: {}, required: [] },
	},
] as const;

export const GARMIN_TOOL_NAMES = new Set<string>(garminToolDefs.map(t => t.name));

const NEEDS_FRESH_DATA = new Set(['garmin_today', 'garmin_trends', 'garmin_activities', 'garmin_records', 'garmin_intraday', 'garmin_activity_detail']);

function backfillLine(bf: BackfillStatus): string {
	const parts = [`days ${bf.done}/${bf.total}`];
	if (bf.already_complete) parts.push(`${bf.already_complete} already stored`);
	if (bf.details_total != null) parts.push(`activity details ${bf.details_done ?? 0}/${bf.details_total}`);
	let line = `${bf.from} → ${bf.to}: ${parts.join(' · ')}`;
	if (bf.phase) line += ` · now: ${bf.phase === 'waiting' ? `paused for Garmin rate limit until ${bf.waiting_until ? localDateTime(Date.parse(bf.waiting_until)) : 'soon'}` : bf.phase}`;
	return line;
}

export async function handleGarminTool(
	name: string,
	args: Record<string, unknown>,
	deps: { store: GarminStore; sync: GarminSync; baseUrl: string }
): Promise<ToolResult> {
	const { store, sync, baseUrl } = deps;
	const reauth = baseUrl ? `${baseUrl}/reauth` : '/reauth on the server';

	if (name === 'garmin_auth_url') {
		return text(`To (re)connect Garmin:\n\n1. Open ${reauth}\n2. Sign in with your Garmin email and password (and the code Garmin sends, if asked)\n3. Syncs resume straight after.`);
	}

	// Pure database tools work even while Garmin is disconnected.
	if (name === 'garmin_schema') {
		const tables = store.schema();
		let out = '# Health database schema (SQLite)\n\n';
		for (const t of tables) out += `## ${t.table} (${t.rows} rows)\n${t.columns.join(', ')}\n\n`;
		out +=
			'Notes: dates are Brisbane calendar dates (YYYY-MM-DD). garmin_intraday.ts and *_gmt epoch values are UTC milliseconds — local time is datetime(ts/1000, \'unixepoch\', \'+10 hours\'). ' +
			'sleep_stage values: 0 deep, 1 light, 2 REM, 3 awake. Speeds are m/s (pace min/km = 1000/60/speed). stride_cm, gct_ms, vert_osc_cm are Garmin units. ' +
			'Raw JSON: garmin_daily_raw.json, or gunzip_json(gz) for gzipped sources; garmin_activity_raw.gz via gunzip_json(gz). WHOOP archive tables: cycles, recovery, sleep, workouts, body_measurement, profile.';
		return capped(out);
	}
	if (name === 'garmin_query') {
		const sql = String(args.sql ?? '');
		const limit = clampInt(args.limit, 500, 1, 5000);
		try {
			const r = store.readonlyQuery(sql, limit);
			return capped(JSON.stringify({ columns: r.columns, rows: r.rows, returned: r.rows.length, truncated: r.truncated }));
		} catch (err) {
			return text(`Query failed: ${err instanceof Error ? err.message : String(err)}`, true);
		}
	}

	if (!sync.isConnected()) {
		return text(`Garmin isn't connected yet. Sign in at ${reauth}, then try again.`, true);
	}

	let syncNote = '';
	// While a backfill holds the sync queue, serve stored data instead of
	// waiting behind it for minutes.
	if (NEEDS_FRESH_DATA.has(name) && !sync.backfillStatus().running) {
		try {
			await sync.smartSync();
		} catch (err) {
			const reason = err instanceof GarminBridgeError && err.status === 401 ? `Garmin session expired — reconnect at ${reauth}` : err instanceof Error ? err.message : String(err);
			console.error('[garmin] pre-tool sync failed; serving cached data:', reason);
			syncNote = `\n\n_Note: live refresh failed (${reason}); showing stored data._`;
		}
	}

	switch (name) {
		case 'garmin_today': {
			const today = localDate(0);
			const row = store.getDaily(today) ?? store.getLatestDaily();
			if (!row) return text(`No Garmin data stored yet. Run garmin_sync first.${syncNote}`);
			const r = row;
			let out = `# Garmin — ${r.date === today ? 'Today' : `Latest (${r.date})`}\n\n`;
			out += `## Readiness: ${fmtNum(r.readiness_score)} ${r.readiness_level ? `(${pretty(r.readiness_level)})` : ''}\n`;
			if (r.readiness_feedback) out += `- Feedback: ${pretty(r.readiness_feedback)}\n`;
			if (r.recovery_time_min != null) out += `- Recovery time: ${fmtNum((r.recovery_time_min as number) / 60, 0)} h\n`;
			if ([r.readiness_sleep_pct, r.readiness_hrv_pct, r.readiness_recovery_pct, r.readiness_acwr_pct, r.readiness_stress_pct].some(isNum)) {
				out += `- Factors: sleep ${fmtNum(r.readiness_sleep_pct)}% · sleep history ${fmtNum(r.readiness_sleep_history_pct)}% · HRV ${fmtNum(r.readiness_hrv_pct)}% · recovery ${fmtNum(r.readiness_recovery_pct)}% · load ${fmtNum(r.readiness_acwr_pct)}% · stress ${fmtNum(r.readiness_stress_pct)}%\n`;
			}
			out += `\n## Last night\n`;
			out += `- Sleep: ${fmtHours(r.sleep_s)} · score ${fmtNum(r.sleep_score)} ${r.sleep_quality ? `(${pretty(r.sleep_quality)})` : ''}\n`;
			out += `- Stages: deep ${fmtHours(r.deep_s)}, light ${fmtHours(r.light_s)}, REM ${fmtHours(r.rem_s)}, awake ${fmtHours(r.awake_s)}\n`;
			if (isNum(r.sleep_start_local) && isNum(r.sleep_end_local)) {
				// *_local timestamps are local wall-clock expressed as if UTC.
				const hm = (ms: number) => new Date(ms).toISOString().slice(11, 16);
				out += `- Window: ${hm(r.sleep_start_local)} → ${hm(r.sleep_end_local)}\n`;
			}
			out += `- HRV: ${fmtNum(r.hrv_last_night)} ms (7-day ${fmtNum(r.hrv_weekly)}; baseline ${fmtNum(r.hrv_baseline_low)}–${fmtNum(r.hrv_baseline_high)}) ${r.hrv_status ? `· ${pretty(r.hrv_status)}` : ''}\n`;
			out += `- Resting HR: ${fmtNum(r.resting_hr)} bpm\n`;
			if (r.sleep_resp_avg != null) out += `- Respiration: ${fmtNum(r.sleep_resp_avg, 1)} br/min\n`;
			if (r.sleep_bb_change != null) out += `- Body Battery recharged overnight: ${fmtNum(r.sleep_bb_change)}\n`;
			out += `\n## Day so far\n`;
			out += `- Body Battery: wake ${fmtNum(r.bb_wake)} · high ${fmtNum(r.bb_high)} · low ${fmtNum(r.bb_low)}\n`;
			out += `- Stress avg: ${fmtNum(r.stress_avg)} · Steps: ${fmtNum(r.steps)} · Active kcal: ${fmtNum(r.active_kcal)}\n`;
			if (r.training_status || r.load_acute != null) {
				out += `\n## Training\n- Status: ${pretty(r.training_status)}\n- Acute load ${fmtNum(r.load_acute)} · chronic ${fmtNum(r.load_chronic)} · ratio ${fmtNum(r.acwr, 2)}\n`;
				if (r.vo2max != null) out += `- VO2 max: ${fmtNum(r.vo2max, 1)}\n`;
			}
			const acts = store.getActivitiesRange(r.date, r.date);
			if (acts.length) {
				out += `\n## Activities\n`;
				for (const a of acts) {
					out += `- ${a.name ?? pretty(a.type_key)} (id ${a.activity_id}): ${fmtHours(a.duration_s)}, avg HR ${fmtNum(a.avg_hr)}, load ${fmtNum(a.training_load)}\n`;
				}
			}
			return text(out + syncNote);
		}

		case 'garmin_trends': {
			const days = clampInt(args.days, 14, 1, 730);
			const rows = store.getDailyRange(localDate(days - 1), localDate(0));
			if (!rows.length) return text(`No Garmin data for that window. Try garmin_sync with days=${days}.${syncNote}`);
			let out = `# Garmin trends — last ${days} days\n\n| Date | Ready | HRV | RHR | Sleep | Score | BB high | Stress | Steps |\n|---|---|---|---|---|---|---|---|---|\n`;
			for (const r of rows) {
				out += `| ${r.date} | ${fmtNum(r.readiness_score)} | ${fmtNum(r.hrv_last_night)} | ${fmtNum(r.resting_hr)} | ${fmtHours(r.sleep_s)} | ${fmtNum(r.sleep_score)} | ${fmtNum(r.bb_high)} | ${fmtNum(r.stress_avg)} | ${fmtNum(r.steps)} |\n`;
			}
			const sleepAvg = avg(rows, 'sleep_s');
			out += `\n**Averages:** readiness ${fmtNum(avg(rows, 'readiness_score'))} · HRV ${fmtNum(avg(rows, 'hrv_last_night'))} ms · RHR ${fmtNum(avg(rows, 'resting_hr'))} bpm · sleep ${fmtHours(sleepAvg)} (score ${fmtNum(avg(rows, 'sleep_score'))}) · stress ${fmtNum(avg(rows, 'stress_avg'))} · steps ${fmtNum(avg(rows, 'steps'))}\n`;
			return capped(out + syncNote);
		}

		case 'garmin_activities': {
			const days = clampInt(args.days, 14, 1, 730);
			const acts = store.getActivitiesRange(localDate(days - 1), localDate(0));
			if (!acts.length) return text(`No Garmin activities in the last ${days} days.${syncNote}`);
			let out = `# Garmin activities — last ${days} days\n\n| When | Activity | id | Time | Dist | Pace | Avg/Max HR | Cad | Aer/Ana TE | Load |\n|---|---|---|---|---|---|---|---|---|---|\n`;
			for (const a of acts) {
				const dist = isNum(a.distance_m) && a.distance_m > 0 ? `${(a.distance_m / 1000).toFixed(2)} km` : '—';
				const pace = isNum(a.distance_m) && a.distance_m > 0 && isRun(a) ? fmtPace(a.avg_speed) : '—';
				out += `| ${String(a.start_local ?? '').slice(0, 16)} | ${a.name ?? pretty(a.type_key)} | ${a.activity_id} | ${fmtHours(a.duration_s)} | ${dist} | ${pace} | ${fmtNum(a.avg_hr)}/${fmtNum(a.max_hr)} | ${fmtNum(a.avg_cadence)} | ${fmtNum(a.aerobic_te, 1)}/${fmtNum(a.anaerobic_te, 1)} | ${fmtNum(a.training_load)} |\n`;
			}
			return capped(out + syncNote);
		}

		case 'garmin_activity_detail': {
			let activity: GarminActivityRow | null = null;
			if (args.activity_id != null) {
				activity = store.getActivity(clampInt(args.activity_id, 0, 0, Number.MAX_SAFE_INTEGER));
				if (!activity) return text(`No stored activity ${args.activity_id}. Check garmin_activities for ids.${syncNote}`, true);
			} else {
				const date = typeof args.date === 'string' && isDate(args.date) ? args.date : null;
				const acts = date ? store.getActivitiesRange(date, date) : store.getActivitiesRange(localDate(729), localDate(0));
				activity = acts[0] ?? null;
				if (!activity) return text(`No activities stored${date ? ` on ${date}` : ''}.${syncNote}`);
			}
			const id = activity.activity_id;

			let detailNote = '';
			if (!store.getActivityDetailState(id) || args.refresh === true) {
				if (sync.backfillStatus().running) {
					detailNote = '\n\n_Detail not fetched yet — the running backfill will pull it._';
				} else {
					try {
						await sync.syncActivityDetail(id);
						activity = store.getActivity(id) ?? activity;
					} catch (err) {
						detailNote = `\n\n_Couldn't fetch detail from Garmin: ${err instanceof Error ? err.message : String(err)}_`;
					}
				}
			}
			const a = activity;
			const run = isRun(a);
			const state = store.getActivityDetailState(id);

			let out = `# ${a.name ?? pretty(a.type_key)} — ${String(a.start_local ?? '').slice(0, 16)}${a.location ? ` · ${a.location}` : ''}\n`;
			out += `id ${id} · ${pretty(a.type_key)}\n\n## Summary\n`;
			const dist = isNum(a.distance_m) && a.distance_m > 0 ? `${(a.distance_m / 1000).toFixed(2)} km` : null;
			out += `- ${dist ? `${dist} in ` : ''}${fmtDuration(a.duration_s)}${isNum(a.moving_s) ? ` (moving ${fmtDuration(a.moving_s)})` : ''}\n`;
			if (run && dist) out += `- Pace ${fmtPace(a.avg_speed)} /km · GAP ${fmtPace(a.gap_speed)} /km · best ${fmtPace(a.max_speed)} /km\n`;
			out += `- HR avg ${fmtNum(a.avg_hr)} · max ${fmtNum(a.max_hr)}${isNum(a.min_hr) ? ` · min ${fmtNum(a.min_hr)}` : ''} bpm\n`;
			if (isNum(a.avg_cadence)) out += `- Cadence avg ${fmtNum(a.avg_cadence)} · max ${fmtNum(a.max_cadence)} spm\n`;
			const dyn = [
				isNum(a.stride_cm) ? `stride ${(a.stride_cm / 100).toFixed(2)} m` : null,
				isNum(a.gct_ms) ? `ground contact ${fmtNum(a.gct_ms)} ms` : null,
				isNum(a.vert_osc_cm) ? `vertical oscillation ${fmtNum(a.vert_osc_cm, 1)} cm` : null,
				isNum(a.vert_ratio) ? `vertical ratio ${fmtNum(a.vert_ratio, 1)}%` : null,
			].filter(Boolean);
			if (dyn.length) out += `- Running dynamics: ${dyn.join(' · ')}\n`;
			if (isNum(a.avg_power)) out += `- Power avg ${fmtNum(a.avg_power)} W · max ${fmtNum(a.max_power)} · normalised ${fmtNum(a.norm_power)}\n`;
			if (isNum(a.elevation_gain) || isNum(a.elevation_loss)) out += `- Elevation +${fmtNum(a.elevation_gain)} / −${fmtNum(a.elevation_loss)} m\n`;
			out += `- Training effect: aerobic ${fmtNum(a.aerobic_te, 1)} · anaerobic ${fmtNum(a.anaerobic_te, 1)}${a.te_label ? ` · ${pretty(a.te_label)}` : ''} · load ${fmtNum(a.training_load)}\n`;
			if (a.aerobic_te_msg || a.anaerobic_te_msg) out += `- Garmin's read: ${[a.aerobic_te_msg, a.anaerobic_te_msg].filter(Boolean).map(pretty).join(' / ')}\n`;
			const misc = [
				isNum(a.kcal) ? `${fmtNum(a.kcal)} kcal` : null,
				isNum(a.sweat_ml) ? `sweat ~${fmtNum(a.sweat_ml)} ml` : null,
				isNum(a.bb_change) ? `Body Battery ${a.bb_change > 0 ? '+' : ''}${fmtNum(a.bb_change)}` : null,
				isNum(a.avg_resp) ? `resp ${fmtNum(a.avg_resp, 1)} br/min` : null,
				isNum(a.vo2max) ? `VO2 max ${fmtNum(a.vo2max)}` : null,
				isNum(a.min_temp_c) || isNum(a.max_temp_c) ? `device temp ${fmtNum(a.min_temp_c)}–${fmtNum(a.max_temp_c)}°C` : null,
			].filter(Boolean);
			if (misc.length) out += `- ${misc.join(' · ')}\n`;

			const weather = store.getActivityRaw(id, 'weather') as Record<string, unknown> | null | undefined;
			if (weather && isNum(weather.temp)) {
				const c = (f: number) => (((f - 32) * 5) / 9).toFixed(0);
				const desc = (weather.weatherTypeDTO as { desc?: unknown } | undefined)?.desc;
				out += `- Weather: ${typeof desc === 'string' ? `${desc}, ` : ''}${fmtNum(weather.temp)}°F (~${c(weather.temp)}°C)${isNum(weather.apparentTemp) ? `, feels ${fmtNum(weather.apparentTemp)}°F (~${c(weather.apparentTemp)}°C)` : ''}${isNum(weather.relativeHumidity) ? `, humidity ${fmtNum(weather.relativeHumidity)}%` : ''}${isNum(weather.windSpeed) ? `, wind ${fmtNum(weather.windSpeed)} mph` : ''}\n`;
			}

			const zones = store.getActivityZones(id);
			const zoneSecs = zones.length ? zones.map(z => ({ zone: z.zone, secs: z.secs ?? 0, low: z.low_bpm })) : [1, 2, 3, 4, 5].map(z => ({ zone: z, secs: isNum(a[`z${z}_s`]) ? (a[`z${z}_s`] as number) : 0, low: null }));
			const zoneTotal = zoneSecs.reduce((s, z) => s + z.secs, 0);
			if (zoneTotal > 0) {
				out += `\n## HR zones\n| Zone | From | Time | % |\n|---|---|---|---|\n`;
				for (const z of zoneSecs) out += `| Z${z.zone} | ${z.low != null ? `${fmtNum(z.low)} bpm` : '—'} | ${fmtDuration(z.secs)} | ${((z.secs / zoneTotal) * 100).toFixed(0)}% |\n`;
			}

			const laps = store.getActivityLaps(id);
			if (laps.length > 1 || (laps.length === 1 && !run)) {
				out += `\n## Laps\n| # | Dist | Time | Pace | GAP | HR avg/max | Cad | Stride | Elev ± | Type |\n|---|---|---|---|---|---|---|---|---|---|\n`;
				for (const l of laps) {
					out += `| ${l.lap_index} | ${isNum(l.distance_m) ? `${(l.distance_m / 1000).toFixed(2)}` : '—'} | ${fmtDuration(l.duration_s)} | ${fmtPace(l.avg_speed)} | ${fmtPace(l.gap_speed)} | ${fmtNum(l.avg_hr)}/${fmtNum(l.max_hr)} | ${fmtNum(l.avg_cadence)} | ${isNum(l.stride_cm) ? (l.stride_cm / 100).toFixed(2) : '—'} | +${fmtNum(l.elevation_gain)}/−${fmtNum(l.elevation_loss)} | ${l.intensity ? pretty(l.intensity) : ''} |\n`;
				}
			}

			const sets = store.getActivitySets(id);
			if (sets.length) {
				out += `\n## Sets\n| # | Exercise | Reps | kg | Time |\n|---|---|---|---|---|\n`;
				let active = 0;
				let volume = 0;
				for (const s of sets) {
					if (s.set_type !== 'ACTIVE') continue;
					active += 1;
					if (isNum(s.reps) && isNum(s.weight_kg)) volume += s.reps * s.weight_kg;
					out += `| ${active} | ${pretty(s.exercise ?? s.category)} | ${fmtNum(s.reps)} | ${isNum(s.weight_kg) ? s.weight_kg : '—'} | ${fmtDuration(s.duration_s)} |\n`;
				}
				out += `\n${active} working sets · volume ${volume.toFixed(0)} kg\n`;
			}

			const details = store.getActivityRaw(id, 'details');
			if (details) {
				const { keys, samples } = parseActivitySeries(details);
				const ins = seriesInsights(samples);
				if (ins) {
					const h = (x: (typeof ins)['first']) =>
						`${run ? `pace ${fmtPace(x.speed)}${x.gap ? ` (GAP ${fmtPace(x.gap)})` : ''}, ` : ''}HR ${fmtNum(x.hr)}${x.cadence ? `, cadence ${fmtNum(x.cadence)}` : ''}`;
					out += `\n## Series analysis (${samples.length} samples)\n`;
					out += `- First half: ${h(ins.first)}\n- Second half: ${h(ins.second)}\n`;
					if (ins.hr_drift_bpm != null) out += `- HR drift: ${ins.hr_drift_bpm >= 0 ? '+' : ''}${ins.hr_drift_bpm.toFixed(1)} bpm\n`;
					if (ins.decoupling_pct != null && run) {
						out += `- Aerobic decoupling (Pa:HR): ${ins.decoupling_pct.toFixed(1)}% — under ~5% suggests the effort sat within aerobic capacity; above ~5% means HR climbed relative to pace (fatigue, heat, effort above aerobic threshold).\n`;
					}
					if (ins.pace_cv_pct != null && run) out += `- Pace variability: ${ins.pace_cv_pct.toFixed(0)}% CV\n`;
				}
				if (args.series === true && samples.length) {
					const res = clampInt(args.resolution_s, 60, 5, 3600);
					const cadenceKey = keys.includes('directDoubleCadence') ? 'directDoubleCadence' : 'directRunCadence';
					const want = ['sumDistance', 'directHeartRate', 'directSpeed', 'directGradeAdjustedSpeed', cadenceKey, 'directElevation', 'directPower'].filter(k => keys.includes(k));
					const rows = resampleSeries(samples, res, want);
					out += `\n## Series (${res}s buckets)\n| t | ${want.map(k => k.replace(/^direct|^sum/, '')).join(' | ')} |\n|${'---|'.repeat(want.length + 1)}\n`;
					for (const r of rows) {
						out += `| ${fmtDuration(r.t_s)} | ${want
							.map(k => {
								const v = r[k];
								if (k === 'directSpeed' || k === 'directGradeAdjustedSpeed') return fmtPace(v);
								if (k === 'sumDistance') return isNum(v) ? (v / 1000).toFixed(2) : '—';
								return fmtNum(v, k === 'directElevation' ? 1 : 0);
							})
							.join(' | ')} |\n`;
					}
				} else if (samples.length) {
					out += `\n_Series stored (${keys.filter(k => !/Latitude|Longitude/.test(k)).map(k => k.replace(/^direct|^sum/, '')).join(', ')}); call with series: true to see it._\n`;
				}
			}
			if (state?.errors) out += `\n_Some detail endpoints returned nothing: ${Object.keys(JSON.parse(state.errors)).join(', ')}._\n`;
			return capped(out + detailNote + syncNote);
		}

		case 'garmin_intraday': {
			const date = typeof args.date === 'string' && isDate(args.date) ? args.date : localDate(0);
			let end = typeof args.end_date === 'string' && isDate(args.end_date) ? args.end_date : date;
			if (end < date) end = date;
			const spanDays = (Date.parse(`${end}T00:00:00Z`) - Date.parse(`${date}T00:00:00Z`)) / 86_400_000;
			if (spanDays > 13) return text('Range too long: at most 14 days per call (use garmin_query for longer windows).', true);
			const resMin = clampInt(args.resolution_min, 15, 1, 240);
			const bucketMs = resMin * 60_000;
			const metric = typeof args.metric === 'string' ? args.metric : null;

			if (metric === 'sleep_stage') {
				const pts = store.getIntraday(date, end, 'sleep_stage');
				if (!pts.length) return text(`No sleep stage data for ${date}${end !== date ? `–${end}` : ''}.${syncNote}`);
				let out = `# Sleep stages — ${date}${end !== date ? ` → ${end}` : ''}\n\n| Start | Stage |\n|---|---|\n`;
				for (const p of pts) out += `| ${localDateTime(p.ts)} | ${SLEEP_STAGE_NAMES[p.value] ?? p.value} |\n`;
				return capped(out + syncNote);
			}

			const metrics = metric ? [metric] : ['hr', 'stress', 'body_battery', 'respiration', 'steps'];
			if (metric && !(INTRADAY_METRICS as readonly string[]).includes(metric)) return text(`metric must be one of: ${INTRADAY_METRICS.join(', ')}.`, true);
			const series = metrics.map(m => ({ m, buckets: bucketIntraday(store.getIntraday(date, end, m), bucketMs, INTRADAY_AGG[m] ?? 'avg') }));
			const allTs = [...new Set(series.flatMap(s => [...s.buckets.keys()]))].sort((a, b) => a - b);
			if (!allTs.length) return text(`No intraday data for ${date}${end !== date ? `–${end}` : ''}. Sync that date (garmin_sync with enough days).${syncNote}`);
			const multiDay = end !== date;
			let out = `# Intraday — ${date}${multiDay ? ` → ${end}` : ''} (${resMin}-min buckets, local time)\n\n| Time | ${metrics.join(' | ')} |\n|${'---|'.repeat(metrics.length + 1)}\n`;
			for (const ts of allTs) {
				out += `| ${multiDay ? localDateTime(ts) : localTime(ts)} | ${series.map(s => fmtNum(s.buckets.get(ts), s.m === 'respiration' ? 1 : 0)).join(' | ')} |\n`;
			}
			out += `\n_Aggregation: ${metrics.map(m => `${m} ${INTRADAY_AGG[m] ?? 'avg'}`).join(', ')}._`;
			return capped(out + syncNote);
		}

		case 'garmin_profile': {
			const kind = typeof args.kind === 'string' ? args.kind : null;
			if (kind) {
				const snap = store.getSnapshot(kind);
				if (snap === undefined) return text(`Nothing stored for ${kind} yet — it is fetched on the next sync.`);
				return capped(JSON.stringify({ kind, data: snap }));
			}
			let out = '# Garmin profile\n';
			const zonesRaw = store.getSnapshot('heart_rate_zones');
			const zoneList = Array.isArray(zonesRaw) ? (zonesRaw as Array<Record<string, unknown>>) : [];
			for (const z of zoneList) {
				if (!isNum(z.zone1Floor)) continue;
				out += `\n## HR zones (${pretty(z.sport ?? 'default')}, method ${pretty(z.trainingMethod)})\n`;
				out += `- Max HR used ${fmtNum(z.maxHeartRateUsed)} · resting ${fmtNum(z.restingHeartRateUsed)} · threshold ${fmtNum(z.lactateThresholdHeartRateUsed)}\n`;
				out += `- Z1 ≥${fmtNum(z.zone1Floor)} · Z2 ≥${fmtNum(z.zone2Floor)} · Z3 ≥${fmtNum(z.zone3Floor)} · Z4 ≥${fmtNum(z.zone4Floor)} · Z5 ≥${fmtNum(z.zone5Floor)} bpm\n`;
			}
			const rp = store.getSnapshot('race_predictions') as Record<string, unknown> | null | undefined;
			if (rp && (isNum(rp.time5K) || isNum(rp.time10K))) {
				out += `\n## Race predictions${rp.calendarDate ? ` (${rp.calendarDate})` : ''}\n- 5K ${fmtDuration(rp.time5K)} · 10K ${fmtDuration(rp.time10K)} · half ${fmtDuration(rp.timeHalfMarathon)} · marathon ${fmtDuration(rp.timeMarathon)}\n`;
			}
			const latest = store.getLatestDaily();
			if (latest?.vo2max != null) out += `\n## VO2 max\n- ${fmtNum(latest.vo2max, 1)} (as of ${latest.date})\n`;
			const settings = store.getSnapshot('user_settings') as Record<string, unknown> | null | undefined;
			const ud = (settings?.userData ?? null) as Record<string, unknown> | null;
			if (ud) {
				const bits = [
					isNum(ud.lactateThresholdHeartRate) ? `LT HR ${fmtNum(ud.lactateThresholdHeartRate)} bpm` : null,
					isNum(ud.vo2MaxRunning) ? `VO2 max (running) ${fmtNum(ud.vo2MaxRunning)}` : null,
					isNum(ud.weight) ? `weight ${(ud.weight / 1000).toFixed(1)} kg` : null,
					isNum(ud.height) ? `height ${fmtNum(ud.height)} cm` : null,
				].filter(Boolean);
				if (bits.length) out += `\n## Settings\n- ${bits.join(' · ')}\n`;
			}
			const kinds = [
				'user_settings', 'heart_rate_zones', 'personal_records', 'race_predictions', 'race_predictions_history', 'lactate_threshold',
				'lactate_threshold_history', 'endurance_score', 'hill_score', 'running_tolerance', 'body_composition', 'devices', 'primary_device', 'goals', 'training_plans',
			];
			const stored = kinds.filter(k => {
				const s = store.getSnapshot(k);
				return s !== undefined && s !== null;
			});
			out += `\n_Datasets stored (call with kind for JSON): ${stored.length ? stored.join(', ') : 'none yet — fetched on the next sync'}._`;
			return capped(out);
		}

		case 'garmin_records': {
			const type = String(args.type ?? '');
			const days = clampInt(args.days, 14, 1, 730);
			const limit = clampInt(args.limit, 500, 1, 2000);
			const start = localDate(days - 1);
			const end = localDate(0);
			let rows: Array<Record<string, unknown>>;
			if (type === 'daily') rows = store.getDailyRange(start, end);
			else if (type === 'activities') rows = store.getActivitiesRange(start, end);
			else return text('Invalid type. Use "daily" or "activities".', true);
			const out = rows.slice(0, limit);
			return capped(JSON.stringify({ type, days, returned: out.length, total_in_window: rows.length, truncated: rows.length > limit, records: out }) + syncNote);
		}

		case 'garmin_raw': {
			const source = String(args.source ?? '');
			if (args.activity_id != null) {
				const id = clampInt(args.activity_id, 0, 0, Number.MAX_SAFE_INTEGER);
				if (!(ACTIVITY_SOURCES as readonly string[]).includes(source)) return text(`For an activity, source must be one of: ${ACTIVITY_SOURCES.join(', ')}.`, true);
				const raw = store.getActivityRaw(id, source);
				if (raw === undefined) return text(`Nothing stored for activity ${id} / ${source}. garmin_activity_detail fetches it.`);
				return capped(JSON.stringify({ activity_id: id, source, data: raw }));
			}
			const date = String(args.date ?? '');
			if (!isDate(date)) return text('date must be YYYY-MM-DD (or pass activity_id for an activity source).', true);
			if (!(DAILY_SOURCES as readonly string[]).includes(source)) return text(`source must be one of: ${DAILY_SOURCES.join(', ')}.`, true);
			const raw = store.getRaw(date, source);
			if (raw === undefined) return text(`Nothing stored for ${date} / ${source}. Sync that date first (garmin_sync with enough days).`);
			return capped(JSON.stringify({ date, source, data: raw }));
		}

		case 'garmin_sync': {
			if (args.days !== undefined && args.days !== null) {
				const days = clampInt(args.days, 30, 1, 730);
				if (days > 7) {
					const status = sync.startBackfill(days, args.refresh === true);
					const mins = Math.ceil((days * 15) / 60);
					return text(
						status.running
							? `Backfill running (${status.from} → ${status.to}). Each day is ~16 Garmin calls, so a full pull takes up to ~${mins} min for ${days} days (days already stored are skipped), then activity details and profile data. It pauses and resumes on Garmin rate limits. Call garmin_sync with no arguments to check progress.\n\nProgress: ${backfillLine(status)}`
							: `Backfill not started: ${JSON.stringify(status)}`
					);
				}
				const r = await sync.syncRange(localDate(days - 1), localDate(0), { refresh: args.refresh === true, detailLimit: 10 });
				return text(`Synced ${r.days} day(s), ${r.activities} activities, ${r.details ?? 0} activity details${r.profile ? ', profile' : ''}.`);
			}
			const bf = sync.backfillStatus();
			if (bf.running) {
				return text(`Backfill in progress — ${backfillLine(bf)}. Stored data is usable meanwhile.`);
			}
			const r = await sync.smartSync();
			const state = store.getSyncState();
			let out =
				r.type === 'skip'
					? 'Garmin data already fresh (synced within the hour).'
					: `Synced ${r.days} day(s), ${r.activities} activities, ${r.details ?? 0} activity details${r.profile ? ', profile' : ''}.`;
			out += `\nStored range: ${state.oldest_date ?? '—'} → ${state.newest_date ?? '—'}.`;
			const pending = store.activitiesNeedingDetail(1000).length;
			if (pending) out += `\n${pending} activities still need detail — they're fetched a few per hourly sync, or all at once by a backfill.`;
			if (bf.total) out += `\nLast backfill: ${backfillLine(bf)}${bf.error ? ` — stopped: ${bf.error}` : ' — complete'}.`;
			return text(out);
		}

		default:
			return text(`Unknown Garmin tool: ${name}`, true);
	}
}
