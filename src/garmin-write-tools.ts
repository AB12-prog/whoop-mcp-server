// src/garmin-write-tools.ts — Garmin workout (any sport) and weigh-in tools.
//
// Every write is two-step: called without `confirm: true` it validates
// everything and returns a preview without touching Garmin; called again with
// `confirm: true` it saves. Destructive tools carry MCP annotations so clients
// can flag them.

import { GarminBridge, GarminBridgeError, GarminSync, localDate } from './garmin.js';

type ToolResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean };
const text = (t: string, isError = false): ToolResult => ({ content: [{ type: 'text', text: t }], ...(isError ? { isError } : {}) });

const confirmProp = {
	confirm: {
		type: 'boolean',
		description: 'Leave unset/false to get a preview (nothing is saved). Set true only after the user has approved that preview.',
	},
};
const scheduleProps = {
	schedule_date: { type: 'string', description: 'Optional YYYY-MM-DD to put it on the Garmin calendar (syncs to the watch).' },
	send_to_watch: { type: 'boolean', description: 'Optional: also push it to the watch right away.' },
};

const lowHigh = (unit: string) => ({
	type: 'object',
	description: `Range in ${unit}: {"low": …, "high": …}`,
	properties: { low: { type: 'number' }, high: { type: 'number' } },
});

const stepProperties = {
	type: { type: 'string', enum: ['warmup', 'interval', 'recovery', 'rest', 'cooldown', 'other', 'repeat'] },
	duration_s: { type: 'number', description: 'Ends after this many seconds.' },
	distance_m: { type: 'number', description: 'Ends after this distance in metres.' },
	reps: { type: 'number', description: 'Ends after this many reps (needs exercise).' },
	calories: { type: 'number', description: 'Ends after this many kcal.' },
	lap_button: { type: 'boolean', description: 'true = open-ended, ends when you press lap.' },
	exercise: { type: 'string', description: "Optional exercise from Garmin's catalogue (cardio, HIIT, yoga, pilates, mobility, strength, other)." },
	weight_kg: { type: 'number', description: 'Optional load in kg for an exercise step.' },
	hr_zone: { type: 'number', description: 'Target heart-rate zone 1–5 (as configured on the watch).' },
	hr_bpm: lowHigh('bpm'),
	pace: {
		type: 'object',
		description: 'Running/walking/hiking pace range per km, e.g. {"fast":"4:50","slow":"5:10"}.',
		properties: { fast: { type: 'string' }, slow: { type: 'string' } },
	},
	speed_kmh: lowHigh('km/h'),
	power_zone: { type: 'number', description: 'Target power zone 1–7.' },
	power_w: lowHigh('watts'),
	cadence: lowHigh('rpm (spm for run/walk/hike)'),
	notes: { type: 'string', description: 'Optional note shown on the watch for this step (max 200 characters).' },
	times: { type: 'number', description: 'repeat only: 2–99' },
};

const stepsSchema = {
	type: 'array',
	description: 'Steps in order. One target per step at most.',
	items: {
		type: 'object',
		properties: {
			...stepProperties,
			steps: { type: 'array', description: 'repeat only: the steps to repeat', items: { type: 'object', properties: stepProperties, required: ['type'] } },
		},
		required: ['type'],
	},
};

const WRITE = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true };
const DESTRUCTIVE = { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true };
const READ = { readOnlyHint: true, openWorldHint: true };

export const garminWriteToolDefs = [
	{
		name: 'garmin_workouts',
		description: 'List workouts in the Garmin workout library (any sport) and those scheduled on the Garmin calendar (this month and next two). Returns the ids the other workout tools need. Use garmin_workout_detail to read one workout step by step.',
		inputSchema: {
			type: 'object',
			properties: { limit: { type: 'number', description: 'Library workouts to list, most recent first (default 30, max 100).' } },
			required: [],
		},
		annotations: READ,
	},
	{
		name: 'garmin_workout_detail',
		description: 'Read one library workout of any sport step by step: step types, durations/distances/reps, exercises, loads (kg), HR/pace/speed/power/cadence targets, repeats and notes.',
		inputSchema: {
			type: 'object',
			properties: { workout_id: { type: 'number', description: 'From garmin_workouts (library).' } },
			required: ['workout_id'],
		},
		annotations: READ,
	},
	{
		name: 'garmin_create_strength_workout',
		description:
			"Create a strength workout in Garmin Connect (optionally schedule it / send to the watch), or replace an existing one in place with workout_id (keeps its calendar dates). Each exercise is sets × reps (or sets × duration_s for holds like planks) with optional load in kg. Exercise names must match Garmin's catalogue; case, spacing and hyphens are forgiven, and an unclear name returns the closest catalogue names to choose from. Two-step: preview first, then confirm.",
		inputSchema: {
			type: 'object',
			properties: {
				name: { type: 'string', description: 'Workout name, max 80 characters.' },
				description: { type: 'string' },
				exercises: {
					type: 'array',
					description: 'In order. Each block = sets of reps (or timed sets) with rest after each set.',
					items: {
						type: 'object',
						properties: {
							exercise: { type: 'string', description: 'e.g. "Barbell Back Squat", "Bench Press", "Pull-up", "Romanian Deadlift", "Plank".' },
							sets: { type: 'number', description: '1–20 (default 3)' },
							reps: { type: 'number', description: '1–200 (default 10). Omit when using duration_s.' },
							duration_s: { type: 'number', description: 'Timed sets instead of reps, 5–3600 s (e.g. a 45 s plank).' },
							weight_kg: { type: 'number', description: 'Optional target load in kg (0–500).' },
							rest_seconds: { type: 'number', description: '0–900 (default 90)' },
						},
						required: ['exercise'],
					},
				},
				workout_id: { type: 'number', description: 'Optional: replace this existing library workout in place instead of creating a new one. Its calendar dates stay.' },
				...scheduleProps,
				...confirmProp,
			},
			required: ['name', 'exercises'],
		},
		annotations: WRITE,
	},
	{
		name: 'garmin_create_workout',
		description:
			'Create a structured workout for ANY sport in Garmin Connect — cycling (indoor or outdoor), running, walking, hiking, pool swimming, cardio machines (rowing, elliptical, stairs, ski erg), HIIT, yoga, pilates, mobility or other — optionally scheduling it / sending it to the watch, or replace an existing one in place with workout_id (keeps its calendar dates). Steps: warmup, interval, recovery, rest, cooldown, other — each ends after duration_s, distance_m, reps (with an exercise), calories, or lap_button. Optional target per step: hr_zone, hr_bpm, pace (run/walk/hike), speed_kmh, power_zone, power_w, or cadence. Use {type:"repeat", times, steps:[...]} for intervals (one level). Two-step: preview first, then confirm.',
		inputSchema: {
			type: 'object',
			properties: {
				sport: {
					type: 'string',
					description:
						'running, cycling, walking, hiking, swimming, cardio_training, hiit, yoga, pilates, mobility, strength_training or other. Aliases: bike, indoor_cycling, spin, treadmill, rowing, rower, elliptical, stairs, ski_erg, walk, hike, swim.',
				},
				name: { type: 'string', description: 'Workout name, max 80 characters.' },
				description: { type: 'string' },
				pool_length_m: { type: 'number', description: 'Swimming only: pool length in metres (default 25).' },
				steps: stepsSchema,
				workout_id: { type: 'number', description: 'Optional: replace this existing library workout in place instead of creating a new one. Its calendar dates stay.' },
				...scheduleProps,
				...confirmProp,
			},
			required: ['sport', 'name', 'steps'],
		},
		annotations: WRITE,
	},
	{
		name: 'garmin_create_run_workout',
		description:
			'Create a structured run workout in Garmin Connect (same as garmin_create_workout with sport "running"). Steps: warmup, interval, recovery, rest, cooldown — each with duration_s, distance_m or lap_button, and an optional target (pace range min:sec per km, hr_zone, hr_bpm, speed_kmh, power or cadence). Use {type:"repeat", times, steps:[...]} for intervals (one level). workout_id replaces an existing workout in place. Two-step: preview first, then confirm.',
		inputSchema: {
			type: 'object',
			properties: {
				name: { type: 'string', description: 'Workout name, max 80 characters.' },
				description: { type: 'string' },
				steps: stepsSchema,
				workout_id: { type: 'number', description: 'Optional: replace this existing library workout in place. Its calendar dates stay.' },
				...scheduleProps,
				...confirmProp,
			},
			required: ['name', 'steps'],
		},
		annotations: WRITE,
	},
	{
		name: 'garmin_schedule_workout',
		description: 'Put an existing library workout on the Garmin calendar for a date (and optionally push it to the watch). Two-step: preview first, then confirm.',
		inputSchema: {
			type: 'object',
			properties: {
				workout_id: { type: 'number', description: 'From garmin_workouts (library).' },
				date: { type: 'string', description: 'YYYY-MM-DD' },
				send_to_watch: { type: 'boolean' },
				...confirmProp,
			},
			required: ['workout_id', 'date'],
		},
		annotations: WRITE,
	},
	{
		name: 'garmin_remove_workout',
		description:
			'Remove a workout: pass scheduled_workout_id to take one date off the calendar (the workout stays in the library), or workout_id to delete it from the library. Two-step: preview first, then confirm.',
		inputSchema: {
			type: 'object',
			properties: {
				scheduled_workout_id: { type: 'number', description: 'From garmin_workouts (scheduled).' },
				workout_id: { type: 'number', description: 'From garmin_workouts (library).' },
				...confirmProp,
			},
			required: [],
		},
		annotations: DESTRUCTIVE,
	},
	{
		name: 'garmin_weigh_ins',
		description: 'Weigh-ins recorded in Garmin Connect (weight, BMI, body fat where available), with the ids needed to delete one.',
		inputSchema: {
			type: 'object',
			properties: { days: { type: 'number', description: 'Days back from today (default 30, max 730).' } },
			required: [],
		},
		annotations: READ,
	},
	{
		name: 'garmin_log_weight',
		description: 'Log a body-weight weigh-in to Garmin Connect (kg). Two-step: preview first, then confirm.',
		inputSchema: {
			type: 'object',
			properties: {
				weight_kg: { type: 'number', description: '25–300 kg' },
				date: { type: 'string', description: 'YYYY-MM-DD, Brisbane date (default today).' },
				time: { type: 'string', description: 'HH:MM 24-hour, Brisbane time (default 07:00).' },
				...confirmProp,
			},
			required: ['weight_kg'],
		},
		annotations: WRITE,
	},
	{
		name: 'garmin_delete_weight',
		description: 'Delete one weigh-in from Garmin Connect (ids from garmin_weigh_ins). Two-step: preview first, then confirm.',
		inputSchema: {
			type: 'object',
			properties: {
				weight_pk: { type: 'number' },
				date: { type: 'string', description: 'YYYY-MM-DD of that weigh-in' },
				...confirmProp,
			},
			required: ['weight_pk', 'date'],
		},
		annotations: DESTRUCTIVE,
	},
] as const;

export const GARMIN_WRITE_TOOL_NAMES = new Set<string>(garminWriteToolDefs.map(t => t.name));

const PREVIEW_FOOTER = '\n\n**Nothing has been saved.** Show this to the user; once they approve, call the same tool again with the same arguments plus `confirm: true`.';

interface Preview {
	[key: string]: unknown;
}
interface BridgeWriteResult {
	status: string;
	preview: Preview;
	workout_id?: number;
	scheduled_workout_id?: number;
	scheduled?: boolean;
	schedule_error?: string;
	sent_to_watch?: boolean;
	send_error?: string;
}

function workoutPreviewText(p: Preview): string {
	let out = `**${p.label ?? (p.kind === 'run' ? 'Run' : 'Strength')} workout: ${p.name}**\n`;
	if (p.replace_workout_id) out += `_Replaces "${p.replace_name ?? 'workout'}" (id ${p.replace_workout_id}) in place — its calendar dates stay._\n`;
	for (const line of (p.steps as string[]) ?? []) out += `- ${line}\n`;
	if (p.schedule_date) out += `\nScheduled for: ${p.schedule_date}`;
	if (p.send_to_watch) out += `\nSend to watch: yes`;
	return out;
}

function followOns(r: BridgeWriteResult): string {
	let out = '';
	if (r.scheduled) out += `\n- Scheduled for ${r.preview.schedule_date ?? r.preview.date}${r.scheduled_workout_id ? ` (scheduled id ${r.scheduled_workout_id})` : ''}`;
	if (r.schedule_error) out += `\n- ⚠️ Created, but scheduling failed: ${r.schedule_error}`;
	if (r.sent_to_watch) out += '\n- Sent to your watch (it arrives on next sync)';
	if (r.send_error) out += `\n- ⚠️ Not sent to the watch: ${r.send_error}`;
	return out;
}

/** Calendar months to scan: this month and the next two, in the owner's time zone. */
function upcomingMonths(): Array<[number, number]> {
	const [y, m] = localDate(0).split('-').map(Number);
	return [0, 1, 2].map(i => {
		const idx = m - 1 + i;
		return [y + Math.floor(idx / 12), (idx % 12) + 1] as [number, number];
	});
}

export async function handleGarminWriteTool(
	name: string,
	args: Record<string, unknown>,
	deps: { bridge: GarminBridge; sync: GarminSync; baseUrl: string }
): Promise<ToolResult> {
	const { bridge, sync, baseUrl } = deps;
	if (!sync.isConnected()) {
		return text(`Garmin isn't connected yet. Sign in at ${baseUrl ? `${baseUrl}/reauth` : '/reauth'}, then try again.`, true);
	}
	const dryRun = args.confirm !== true;

	try {
		switch (name) {
			case 'garmin_workouts': {
				const lim = Number(args.limit ?? 30);
				const limit = Number.isFinite(lim) ? Math.min(Math.max(Math.trunc(lim), 1), 100) : 30;
				const r = await bridge.call<{ library: Preview[]; scheduled: Preview[] }>('/workouts/list', { months: upcomingMonths(), limit });
				const today = localDate(0);
				const upcoming = r.scheduled.filter(s => String(s.date ?? '') >= today);
				let out = '# Garmin workouts\n\n## Scheduled (today onward)\n';
				out += upcoming.length
					? upcoming.map(s => `- ${s.date} — ${s.name} (${s.sport ?? 'workout'}) · scheduled id ${s.scheduled_workout_id}, workout id ${s.workout_id}`).join('\n')
					: '- Nothing scheduled';
				out += `\n\n## Library (most recent ${limit})\n`;
				out += r.library.length
					? r.library.map(w => `- ${w.name} (${w.sport ?? 'no sport set'}) · workout id ${w.workout_id}`).join('\n')
					: '- Library is empty';
				return text(out);
			}

			case 'garmin_workout_detail': {
				const r = await bridge.call<Preview>('/workouts/detail', { workout_id: args.workout_id });
				let out = `# ${r.name ?? 'Workout'} (${r.sport ?? 'no sport set'}) · workout id ${r.workout_id}\n`;
				if (r.description) out += `\n${r.description}\n`;
				if (typeof r.pool_length_m === 'number') out += `\nPool length: ${r.pool_length_m} m\n`;
				out += '\n';
				const steps = (r.steps as string[]) ?? [];
				out += steps.length ? steps.map(l => `- ${l}`).join('\n') : '- No steps';
				return text(out);
			}

			case 'garmin_create_strength_workout':
			case 'garmin_create_run_workout':
			case 'garmin_create_workout': {
				const kind = name === 'garmin_create_strength_workout' ? 'strength' : name === 'garmin_create_run_workout' ? 'run' : 'sport';
				const r = await bridge.call<BridgeWriteResult>(
					'/workouts/create',
					{
						kind,
						sport: args.sport,
						name: args.name,
						description: args.description,
						exercises: args.exercises,
						steps: args.steps,
						pool_length_m: args.pool_length_m,
						workout_id: args.workout_id,
						schedule_date: args.schedule_date,
						send_to_watch: args.send_to_watch === true,
						dry_run: dryRun,
					},
					120_000
				);
				if (r.status === 'preview') return text(`${workoutPreviewText(r.preview)}${PREVIEW_FOOTER}`);
				if (r.status === 'updated') {
					return text(`✅ Replaced "${r.preview.replace_name ?? r.preview.name}" with "${r.preview.name}" in place (workout id ${r.workout_id}); its calendar dates are unchanged.${followOns(r)}`);
				}
				return text(`✅ Created "${r.preview.name}" in Garmin Connect (workout id ${r.workout_id}).${followOns(r)}`);
			}

			case 'garmin_schedule_workout': {
				const r = await bridge.call<BridgeWriteResult>('/workouts/schedule', {
					workout_id: args.workout_id,
					date: args.date,
					send_to_watch: args.send_to_watch === true,
					dry_run: dryRun,
				});
				if (r.status === 'preview') {
					return text(`**Schedule "${r.preview.name}" on ${r.preview.date}**${r.preview.send_to_watch ? ' and send to watch' : ''}${PREVIEW_FOOTER}`);
				}
				return text(`✅ "${r.preview.name}" scheduled for ${r.preview.date}${r.scheduled_workout_id ? ` (scheduled id ${r.scheduled_workout_id})` : ''}.${followOns({ ...r, scheduled: false })}`);
			}

			case 'garmin_remove_workout': {
				const hasSched = args.scheduled_workout_id != null;
				const hasLib = args.workout_id != null;
				if (hasSched === hasLib) return text('Pass exactly one of scheduled_workout_id (unschedule one date) or workout_id (delete from library).', true);
				if (hasSched) {
					const r = await bridge.call<BridgeWriteResult>('/workouts/unschedule', { scheduled_workout_id: args.scheduled_workout_id, dry_run: dryRun });
					const label = `"${r.preview.name ?? 'workout'}" on ${r.preview.date ?? 'its date'}`;
					if (r.status === 'preview') return text(`**Remove ${label} from the calendar** (it stays in the library).${PREVIEW_FOOTER}`);
					return text(`✅ Removed ${label} from the calendar.`);
				}
				const r = await bridge.call<BridgeWriteResult>('/workouts/delete', { workout_id: args.workout_id, dry_run: dryRun });
				if (r.status === 'preview') return text(`**Delete "${r.preview.name}" from the Garmin workout library.** Any calendar entries for it go too.${PREVIEW_FOOTER}`);
				return text(`✅ Deleted "${r.preview.name}" from the library.`);
			}

			case 'garmin_weigh_ins': {
				const n = Number(args.days ?? 30);
				const days = Number.isFinite(n) ? Math.min(Math.max(Math.trunc(n), 1), 730) : 30;
				const r = await bridge.call<{ weigh_ins: Preview[] }>('/weight/list', { start: localDate(days - 1), end: localDate(0) });
				if (!r.weigh_ins.length) return text(`No weigh-ins in Garmin Connect for the last ${days} days.`);
				let out = `# Weigh-ins — last ${days} days\n\n| Date | Weight | BMI | Body fat | Source | id |\n|---|---|---|---|---|---|\n`;
				for (const w of r.weigh_ins) {
					const fmt = (v: unknown, d = 1, suffix = '') => (typeof v === 'number' ? `${v.toFixed(d)}${suffix}` : '—');
					out += `| ${w.date} | ${fmt(w.weight_kg, 1, ' kg')} | ${fmt(w.bmi)} | ${fmt(w.body_fat_pct, 1, '%')} | ${w.source ?? '—'} | ${w.weight_pk} |\n`;
				}
				return text(out);
			}

			case 'garmin_log_weight': {
				const r = await bridge.call<BridgeWriteResult>('/weight/add', {
					weight_kg: args.weight_kg,
					date: typeof args.date === 'string' && args.date ? args.date : localDate(0),
					time: args.time,
					dry_run: dryRun,
				});
				const p = r.preview;
				if (r.status === 'preview') return text(`**Log weigh-in: ${p.weight_kg} kg on ${p.date} at ${p.time}** (Brisbane time)${PREVIEW_FOOTER}`);
				return text(`✅ Logged ${p.weight_kg} kg for ${p.date} ${p.time} in Garmin Connect.`);
			}

			case 'garmin_delete_weight': {
				const r = await bridge.call<BridgeWriteResult>('/weight/delete', { weight_pk: args.weight_pk, date: args.date, dry_run: dryRun });
				const p = r.preview;
				if (r.status === 'preview') return text(`**Delete weigh-in: ${p.weight_kg ?? '?'} kg on ${p.date}** (source ${p.source ?? 'unknown'})${PREVIEW_FOOTER}`);
				return text(`✅ Deleted the ${p.weight_kg ?? ''} kg weigh-in from ${p.date}.`);
			}

			default:
				return text(`Unknown Garmin tool: ${name}`, true);
		}
	} catch (err) {
		if (err instanceof GarminBridgeError) {
			if (err.status === 401) {
				return text(`Garmin session expired — reconnect at ${baseUrl ? `${baseUrl}/reauth` : '/reauth'}, then try again.`, true);
			}
			// Validation messages (unknown exercise, bad pace, etc.) are written to be shown as-is.
			return text(err.message, true);
		}
		throw err;
	}
}
