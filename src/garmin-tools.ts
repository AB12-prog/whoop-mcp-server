// src/garmin-tools.ts — MCP tool definitions and handlers for Garmin data.

import { GarminBridgeError, GarminStore, GarminSync, RAW_SOURCES, localDate, type GarminDailyRow, type RawSource } from './garmin.js';

type ToolResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean };

const text = (t: string, isError = false): ToolResult => ({ content: [{ type: 'text', text: t }], ...(isError ? { isError } : {}) });

function clampInt(value: unknown, fallback: number, min: number, max: number): number {
	const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
	if (!Number.isFinite(n)) return fallback;
	return Math.min(Math.max(Math.trunc(n), min), max);
}

const fmtNum = (v: unknown, digits = 0): string => (typeof v === 'number' && Number.isFinite(v) ? v.toFixed(digits) : '—');

function fmtHours(seconds: unknown): string {
	if (typeof seconds !== 'number' || !Number.isFinite(seconds)) return '—';
	const h = Math.floor(seconds / 3600);
	const m = Math.round((seconds % 3600) / 60);
	return `${h}h ${String(m).padStart(2, '0')}m`;
}

function avg(rows: GarminDailyRow[], key: string): number | null {
	const vals = rows.map(r => r[key]).filter((v): v is number => typeof v === 'number' && Number.isFinite(v));
	return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
}

const pretty = (s: unknown): string => (typeof s === 'string' ? s.replace(/_/g, ' ').toLowerCase() : '—');

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
		description: 'Garmin-recorded activities (runs, strength, rides, etc.) with duration, distance, HR, training effect, training load and HR-zone time.',
		inputSchema: {
			type: 'object',
			properties: { days: { type: 'number', description: 'Days back from today (default 14, max 730).' } },
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
			"Garmin's raw JSON response for one date and source — use for detail not in the normalised rows (e.g. sleep stage timeline, HRV readings, readiness factors). Sources: summary, sleep, hrv, readiness, training_status.",
		inputSchema: {
			type: 'object',
			properties: {
				date: { type: 'string', description: 'YYYY-MM-DD (Brisbane calendar date). Sleep is filed under the morning it ended.' },
				source: { type: 'string', enum: [...RAW_SOURCES] },
			},
			required: ['date', 'source'],
		},
	},
	{
		name: 'garmin_sync',
		description:
			'Sync Garmin data. With no days: refresh yesterday and today. With days > 7: start a background historical backfill of that many days (paced to avoid rate limits) — call again with no arguments to see progress.',
		inputSchema: {
			type: 'object',
			properties: { days: { type: 'number', description: 'Optional: backfill this many days (max 730).' } },
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

const NEEDS_FRESH_DATA = new Set(['garmin_today', 'garmin_trends', 'garmin_activities', 'garmin_records']);

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
			out += `\n## Last night\n`;
			out += `- Sleep: ${fmtHours(r.sleep_s)} · score ${fmtNum(r.sleep_score)} ${r.sleep_quality ? `(${pretty(r.sleep_quality)})` : ''}\n`;
			out += `- Stages: deep ${fmtHours(r.deep_s)}, light ${fmtHours(r.light_s)}, REM ${fmtHours(r.rem_s)}, awake ${fmtHours(r.awake_s)}\n`;
			out += `- HRV: ${fmtNum(r.hrv_last_night)} ms (7-day ${fmtNum(r.hrv_weekly)}; baseline ${fmtNum(r.hrv_baseline_low)}–${fmtNum(r.hrv_baseline_high)}) ${r.hrv_status ? `· ${pretty(r.hrv_status)}` : ''}\n`;
			out += `- Resting HR: ${fmtNum(r.resting_hr)} bpm\n`;
			if (r.sleep_resp_avg != null) out += `- Respiration: ${fmtNum(r.sleep_resp_avg, 1)} br/min\n`;
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
					out += `- ${a.name ?? pretty(a.type_key)}: ${fmtHours(a.duration_s)}, avg HR ${fmtNum(a.avg_hr)}, load ${fmtNum(a.training_load)}\n`;
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
			return text(out + syncNote);
		}

		case 'garmin_activities': {
			const days = clampInt(args.days, 14, 1, 730);
			const acts = store.getActivitiesRange(localDate(days - 1), localDate(0));
			if (!acts.length) return text(`No Garmin activities in the last ${days} days.${syncNote}`);
			let out = `# Garmin activities — last ${days} days\n\n| When | Activity | Time | Dist | Avg/Max HR | Aer/Ana TE | Load |\n|---|---|---|---|---|---|---|\n`;
			for (const a of acts) {
				const dist = typeof a.distance_m === 'number' && a.distance_m > 0 ? `${(a.distance_m / 1000).toFixed(2)} km` : '—';
				out += `| ${String(a.start_local ?? '').slice(0, 16)} | ${a.name ?? pretty(a.type_key)} | ${fmtHours(a.duration_s)} | ${dist} | ${fmtNum(a.avg_hr)}/${fmtNum(a.max_hr)} | ${fmtNum(a.aerobic_te, 1)}/${fmtNum(a.anaerobic_te, 1)} | ${fmtNum(a.training_load)} |\n`;
			}
			return text(out + syncNote);
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
			return text(JSON.stringify({ type, days, returned: out.length, total_in_window: rows.length, truncated: rows.length > limit, records: out }) + syncNote);
		}

		case 'garmin_raw': {
			const date = String(args.date ?? '');
			const source = String(args.source ?? '') as RawSource;
			if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return text('date must be YYYY-MM-DD.', true);
			if (!RAW_SOURCES.includes(source)) return text(`source must be one of: ${RAW_SOURCES.join(', ')}.`, true);
			const raw = store.getRaw(date, source);
			if (raw === undefined) return text(`Nothing stored for ${date}. Sync that date first (garmin_sync with enough days).`);
			return text(JSON.stringify({ date, source, data: raw }));
		}

		case 'garmin_sync': {
			if (args.days !== undefined && args.days !== null) {
				const days = clampInt(args.days, 30, 1, 730);
				if (days > 7) {
					const status = sync.startBackfill(days);
					return text(
						status.running
							? `Backfill running: ${status.done}/${status.total} days (${status.from} → ${status.to}). Paced at ~2–3 s/day, so ${days} days takes roughly ${Math.ceil((days * 3) / 60)} min. Call garmin_sync with no arguments to check progress.`
							: `Backfill not started: ${JSON.stringify(status)}`
					);
				}
				const r = await sync.syncRange(localDate(days - 1), localDate(0));
				return text(`Synced ${r.days} day(s) and ${r.activities} activities.`);
			}
			const bf = sync.backfillStatus();
			if (bf.running) {
				return text(`Backfill in progress: ${bf.done}/${bf.total} days (${bf.from} → ${bf.to}). Stored data is usable meanwhile.`);
			}
			const r = await sync.smartSync();
			const state = store.getSyncState();
			let out = r.type === 'skip' ? 'Garmin data already fresh (synced within the hour).' : `Synced ${r.days} day(s) and ${r.activities} activities.`;
			out += `\nStored range: ${state.oldest_date ?? '—'} → ${state.newest_date ?? '—'}.`;
			if (bf.total) {
				out += bf.running
					? `\nBackfill in progress: ${bf.done}/${bf.total} days.`
					: `\nLast backfill: ${bf.done}/${bf.total} days${bf.error ? ` — stopped: ${bf.error}` : ' — complete'}.`;
			}
			return text(out);
		}

		default:
			return text(`Unknown Garmin tool: ${name}`, true);
	}
}
