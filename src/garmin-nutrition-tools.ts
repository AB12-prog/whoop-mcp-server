// src/garmin-nutrition-tools.ts — Garmin Connect+ food logging (read + write).
//
// Mirrors the Cronometer connector's shape: search foods, read the day's log,
// add entries, quick-add by macros, create custom foods, remove entries and
// copy a day. Writes are two-step like the other Garmin write tools: without
// `confirm: true` they validate and preview; with it they save.

import { GarminBridge, GarminBridgeError, GarminStore, GarminSync, localDate, parseFoodLog, type FoodEntry } from './garmin.js';

type ToolResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean };
const text = (t: string, isError = false): ToolResult => ({ content: [{ type: 'text', text: t }], ...(isError ? { isError } : {}) });

const PREVIEW_FOOTER = '\n\n**Nothing has been saved.** Show this to the user; once they approve, call the same tool again with the same arguments plus `confirm: true`.';

const WRITE = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true };
const DESTRUCTIVE = { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true };
const READ = { readOnlyHint: true, openWorldHint: true };

const confirmProp = {
	confirm: { type: 'boolean', description: 'Leave unset/false to get a preview (nothing is saved). Set true only after the user has approved that preview.' },
};
const mealProps = {
	date: { type: 'string', description: 'YYYY-MM-DD (default today, Brisbane).' },
	meal: { type: 'string', enum: ['BREAKFAST', 'LUNCH', 'DINNER', 'SNACKS'], description: 'Meal to file under. Omit to pick by time.' },
	time: { type: 'string', description: 'Optional HH:MM eaten (local). Defaults to the meal window start, or now for snacks.' },
};

export const garminNutritionToolDefs = [
	{
		name: 'garmin_food_search',
		description:
			"Search Garmin's food catalogue (FatSecret + Garmin) and your own custom foods. Returns food_id, source and each serving's serving_id with calories and macros — the ids garmin_food_add needs. Requires Garmin Connect+ nutrition.",
		inputSchema: {
			type: 'object',
			properties: {
				query: { type: 'string', description: 'Food or brand, e.g. "greek yoghurt", "Chobani", "banana".' },
				limit: { type: 'number', description: 'Max results per source (default 10, max 50).' },
				include_my_foods: { type: 'boolean', description: 'Also search your custom foods (default true).' },
			},
			required: ['query'],
		},
		annotations: READ,
	},
	{
		name: 'garmin_food_log',
		description:
			"Read a day's Garmin food log: each meal's entries (with log ids for removal), servings, calories and macros, day totals against Garmin's calorie and macro goals.",
		inputSchema: { type: 'object', properties: { date: { type: 'string', description: 'YYYY-MM-DD (default today).' } }, required: [] },
		annotations: READ,
	},
	{
		name: 'garmin_food_add',
		description:
			'Log one or more catalogue/custom foods to a meal in Garmin Connect. Get food_id + serving_id from garmin_food_search (or garmin_food_create_custom). servings multiplies ONE whole serving: 150 g of a "100 g" serving is 1.5. Two-step: preview first, then confirm.',
		inputSchema: {
			type: 'object',
			properties: {
				...mealProps,
				items: {
					type: 'array',
					items: {
						type: 'object',
						properties: {
							food_id: { type: 'string' },
							serving_id: { type: 'string' },
							servings: { type: 'number', description: 'Multiplier of the serving (default 1).' },
							source: { type: 'string', enum: ['FATSECRET', 'GARMIN'], description: 'From search; inferred from the id if omitted.' },
							region: { type: 'string', description: 'regionCode from search, if given.' },
							label: { type: 'string', description: 'Display name for the preview, e.g. "Banana (1 medium) — 105 kcal".' },
						},
						required: ['food_id', 'serving_id'],
					},
				},
				...confirmProp,
			},
			required: ['items'],
		},
		annotations: WRITE,
	},
	{
		name: 'garmin_food_quick_add',
		description:
			'Quick-add entries to a Garmin meal by name and calories/macros, no catalogue food needed — e.g. copying a Cronometer day across, or a restaurant meal. Two-step: preview first, then confirm.',
		inputSchema: {
			type: 'object',
			properties: {
				...mealProps,
				items: {
					type: 'array',
					items: {
						type: 'object',
						properties: {
							name: { type: 'string' },
							calories: { type: 'number', description: 'kcal' },
							protein: { type: 'number', description: 'g' },
							carbs: { type: 'number', description: 'g' },
							fat: { type: 'number', description: 'g' },
						},
						required: ['name', 'calories'],
					},
				},
				...confirmProp,
			},
			required: ['items'],
		},
		annotations: WRITE,
	},
	{
		name: 'garmin_food_create_custom',
		description:
			'Create a custom food in your Garmin library (nutrition per serving, absolute amounts — not %DV). Returns its food_id and serving_id for garmin_food_add. Checks for an existing custom food with the same name first. Two-step: preview first, then confirm.',
		inputSchema: {
			type: 'object',
			properties: {
				name: { type: 'string' },
				brand: { type: 'string' },
				serving_size: { type: 'number', description: 'Amount per serving in serving_unit (default 100).' },
				serving_unit: { type: 'string', description: 'G, ML, OZ, CUP, PIECE… (default G).' },
				calories: { type: 'number' },
				protein: { type: 'number', description: 'g' },
				carbs: { type: 'number', description: 'g' },
				fat: { type: 'number', description: 'g' },
				fiber: { type: 'number', description: 'g' },
				sugar: { type: 'number', description: 'g' },
				saturated_fat: { type: 'number', description: 'g' },
				sodium: { type: 'number', description: 'mg' },
				cholesterol: { type: 'number', description: 'mg' },
				potassium: { type: 'number', description: 'mg' },
				calcium: { type: 'number', description: 'mg' },
				iron: { type: 'number', description: 'mg' },
				...confirmProp,
			},
			required: ['name', 'calories'],
		},
		annotations: WRITE,
	},
	{
		name: 'garmin_food_remove',
		description: 'Remove one or more entries from a day\'s Garmin food log (log ids from garmin_food_log). Two-step: preview first, then confirm.',
		inputSchema: {
			type: 'object',
			properties: {
				date: { type: 'string', description: 'YYYY-MM-DD of the entries.' },
				log_ids: { type: 'array', items: { type: 'string' } },
				...confirmProp,
			},
			required: ['date', 'log_ids'],
		},
		annotations: DESTRUCTIVE,
	},
	{
		name: 'garmin_food_copy_day',
		description: "Copy a day's Garmin food log (or chosen meals) onto another date, into the same meals. Two-step: preview first, then confirm.",
		inputSchema: {
			type: 'object',
			properties: {
				from_date: { type: 'string', description: 'YYYY-MM-DD to copy from.' },
				to_date: { type: 'string', description: 'YYYY-MM-DD to copy to (default today).' },
				meals: { type: 'array', items: { type: 'string', enum: ['BREAKFAST', 'LUNCH', 'DINNER', 'SNACKS'] }, description: 'Only these meals (default all).' },
				...confirmProp,
			},
			required: ['from_date'],
		},
		annotations: WRITE,
	},
] as const;

export const GARMIN_NUTRITION_TOOL_NAMES = new Set<string>(garminNutritionToolDefs.map(t => t.name));

const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const n0 = (v: unknown) => (isNum(v) ? Math.round(v).toString() : '—');
const n1 = (v: unknown) => (isNum(v) ? (Math.round(v * 10) / 10).toString() : '—');
const day = (v: unknown) => (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : localDate(0));
const mealLabel = (m: unknown) => (typeof m === 'string' ? m.charAt(0) + m.slice(1).toLowerCase() : 'Meal');
const MEAL_ORDER = ['BREAKFAST', 'LUNCH', 'DINNER', 'SNACKS'];

interface FoodDay {
	date: string;
	log: Record<string, unknown> | null;
	settings: Record<string, unknown> | null;
	settings_error?: string;
}

/** Re-read a date's log from Garmin and store it, returning the parsed entries. */
async function refreshDay(bridge: GarminBridge, store: GarminStore, date: string): Promise<FoodDay> {
	const r = await bridge.call<FoodDay>('/food/day', { date });
	const totals = (r.log?.dailyNutritionContent ?? {}) as Record<string, unknown>;
	const entries = parseFoodLog(date, r.log);
	store.upsertFoodLog(date, r.log, {
		food_kcal: totals.calories,
		food_protein_g: totals.protein,
		food_carbs_g: totals.carbs,
		food_fat_g: totals.fat,
		food_fiber_g: totals.fiber,
		food_items: r.log ? entries.length : null,
	});
	return r;
}

function renderDay(r: FoodDay): string {
	const entries = parseFoodLog(r.date, r.log);
	const totals = (r.log?.dailyNutritionContent ?? {}) as Record<string, unknown>;
	const goals = r.settings ?? {};
	const macroGoals = (goals.macroGoals ?? {}) as Record<string, unknown>;
	let out = `# Garmin food log — ${r.date}\n`;
	if (!entries.length) out += '\nNothing logged yet.\n';
	const byMeal = new Map<string, FoodEntry[]>();
	for (const e of entries) {
		const k = String(e.meal ?? 'OTHER');
		byMeal.set(k, [...(byMeal.get(k) ?? []), e]);
	}
	const meals = [...byMeal.keys()].sort((a, b) => (MEAL_ORDER.indexOf(a) + 1 || 9) - (MEAL_ORDER.indexOf(b) + 1 || 9));
	for (const m of meals) {
		const list = byMeal.get(m) ?? [];
		const kcal = list.reduce((s, e) => s + (isNum(e.kcal) ? e.kcal : 0), 0);
		out += `\n## ${mealLabel(m)} — ${n0(kcal)} kcal\n| Food | Amount | kcal | P | C | F | log id |\n|---|---|---|---|---|---|---|\n`;
		for (const e of list) {
			const amount =
				e.category === 'QUICK_ADD'
					? 'quick add'
					: `${n1(e.servings)} × ${isNum(e.serving_units) && e.serving_units !== 1 ? `${e.serving_units} ` : ''}${e.serving_unit ?? 'serving'}`;
			out += `| ${e.name ?? '—'}${e.brand ? ` (${e.brand})` : ''} | ${amount} | ${n0(e.kcal)} | ${n1(e.protein_g)} | ${n1(e.carbs_g)} | ${n1(e.fat_g)} | ${e.log_id} |\n`;
		}
	}
	const goalKcal = goals.calorieGoal;
	out += `\n**Day total:** ${n0(totals.calories)} kcal${isNum(goalKcal) ? ` of ${n0(goalKcal)} goal` : ''} · protein ${n1(totals.protein)} g · carbs ${n1(totals.carbs)} g · fat ${n1(totals.fat)} g${isNum(totals.fiber) ? ` · fibre ${n1(totals.fiber)} g` : ''}\n`;
	if ([macroGoals.protein, macroGoals.carbs, macroGoals.fat].some(isNum)) {
		out += `**Garmin macro goals (as stored):** protein ${n0(macroGoals.protein)} · carbs ${n0(macroGoals.carbs)} · fat ${n0(macroGoals.fat)}\n`;
	}
	return out;
}

interface Preview {
	date?: string;
	meal?: string;
	meal_time?: string;
	items?: Array<Record<string, unknown>>;
	entries?: Array<Record<string, unknown>>;
	[k: string]: unknown;
}

export async function handleGarminNutritionTool(
	name: string,
	args: Record<string, unknown>,
	deps: { bridge: GarminBridge; store: GarminStore; sync: GarminSync; baseUrl: string }
): Promise<ToolResult> {
	const { bridge, store, sync, baseUrl } = deps;
	const reauth = baseUrl ? `${baseUrl}/reauth` : '/reauth';
	if (!sync.isConnected()) return text(`Garmin isn't connected yet. Sign in at ${reauth}, then try again.`, true);
	const dryRun = args.confirm !== true;

	try {
		switch (name) {
			case 'garmin_food_search': {
				const r = await bridge.call<{ results: Array<Record<string, unknown>>; more: boolean; errors: Record<string, string> }>('/food/search', {
					query: args.query,
					limit: isNum(args.limit) ? Math.min(Math.max(Math.trunc(args.limit), 1), 50) : 10,
					include_custom: args.include_my_foods !== false,
				});
				if (!r.results.length) return text(`No Garmin foods matched "${String(args.query)}". Try a simpler name, or quick-add it / create a custom food.`);
				let out = `# Garmin food search — "${String(args.query)}"\n`;
				for (const f of r.results) {
					out += `\n**${f.name}**${f.brand ? ` — ${f.brand}` : ''}${f.mine ? ' _(my food)_' : ''} · food_id \`${f.food_id}\` · source ${f.source ?? '—'}${f.region ? ` · region ${f.region}` : ''}\n`;
					for (const s of (f.servings as Array<Record<string, unknown>>) ?? []) {
						const size = `${s.units != null && s.units !== 1 ? `${s.units} ` : ''}${s.unit ?? 'serving'}`;
						out += `- ${size}: ${n0(s.kcal)} kcal · P ${n1(s.protein_g)} · C ${n1(s.carbs_g)} · F ${n1(s.fat_g)} g · serving_id \`${s.serving_id}\`\n`;
					}
				}
				if (r.more) out += '\n_More results available — refine the search._';
				if (r.errors.custom) out += `\n_Custom foods couldn't be searched: ${r.errors.custom}_`;
				return text(out);
			}

			case 'garmin_food_log': {
				const r = await refreshDay(bridge, store, day(args.date));
				let out = renderDay(r);
				if (r.settings_error) out += `\n_Goals unavailable: ${r.settings_error}_`;
				return text(out);
			}

			case 'garmin_food_add': {
				const date = day(args.date);
				const r = await bridge.call<{ status: string; preview: Preview }>('/food/log/add', {
					date, meal: args.meal, time: args.time, items: args.items, dry_run: dryRun,
				});
				const p = r.preview;
				const lines = (p.items ?? []).map(i => `- ${i.label ?? `food ${i.food_id}`} — ${i.servings} × serving \`${i.serving_id}\` (${i.source})`).join('\n');
				if (r.status === 'preview') return text(`**Add to ${mealLabel(p.meal)} on ${p.date}** (filed at ${p.meal_time}):\n${lines}${PREVIEW_FOOTER}`);
				const after = await refreshDay(bridge, store, date);
				return text(`✅ Logged ${p.items?.length ?? 0} item(s) to ${mealLabel(p.meal)} on ${p.date}.\n\n${renderDay(after)}`);
			}

			case 'garmin_food_quick_add': {
				const date = day(args.date);
				const r = await bridge.call<{ status: string; preview: Preview }>('/food/quick_add', {
					date, meal: args.meal, time: args.time, items: args.items, dry_run: dryRun,
				});
				const p = r.preview;
				const items = p.items ?? [];
				const lines = items.map(i => `- ${i.name} — ${n0(i.kcal)} kcal · P ${n1(i.protein_g)} · C ${n1(i.carbs_g)} · F ${n1(i.fat_g)} g`).join('\n');
				const total = items.reduce((s, i) => s + (isNum(i.kcal) ? i.kcal : 0), 0);
				if (r.status === 'preview') return text(`**Quick-add to ${mealLabel(p.meal)} on ${p.date}** (${n0(total)} kcal total):\n${lines}${PREVIEW_FOOTER}`);
				const after = await refreshDay(bridge, store, date);
				return text(`✅ Quick-added ${items.length} item(s) to ${mealLabel(p.meal)} on ${p.date}.\n\n${renderDay(after)}`);
			}

			case 'garmin_food_create_custom': {
				const r = await bridge.call<{ status: string; preview: Preview; food?: Record<string, unknown> | null }>('/food/custom/create', {
					name: args.name, brand: args.brand, serving_size: args.serving_size, serving_unit: args.serving_unit, calories: args.calories,
					protein: args.protein, carbs: args.carbs, fat: args.fat, fiber: args.fiber, sugar: args.sugar, saturated_fat: args.saturated_fat,
					sodium: args.sodium, cholesterol: args.cholesterol, potassium: args.potassium, calcium: args.calcium, iron: args.iron,
					dry_run: dryRun,
				});
				const p = r.preview;
				const ps = (p.per_serving ?? {}) as Record<string, unknown>;
				const existing = p.existing as Record<string, unknown> | null | undefined;
				if (r.status === 'preview') {
					let out = `**Create custom food "${p.name}"**${p.brand ? ` (${p.brand})` : ''} — per ${ps.numberOfUnits} ${ps.servingUnit}: ${ps.calories} kcal · P ${ps.protein ?? '—'} · C ${ps.carbs ?? '—'} · F ${ps.fat ?? '—'} g`;
					if (existing) {
						const s = ((existing.servings as Array<Record<string, unknown>>) ?? [])[0] ?? {};
						out += `\n\n⚠️ A custom food with this name already exists (food_id \`${existing.food_id}\`, serving_id \`${s.serving_id}\`). You can log that one instead of creating a duplicate.`;
					}
					return text(out + PREVIEW_FOOTER);
				}
				const f = r.food;
				const s = ((f?.servings as Array<Record<string, unknown>>) ?? [])[0];
				return text(
					f?.food_id && s?.serving_id
						? `✅ Created "${p.name}" — food_id \`${f.food_id}\`, serving_id \`${s.serving_id}\` (source GARMIN). Use these with garmin_food_add.`
						: `✅ Created "${p.name}". Garmin didn't return its ids — find them with garmin_food_search.`
				);
			}

			case 'garmin_food_remove': {
				if (typeof args.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(args.date)) return text('date (YYYY-MM-DD) is required.', true);
				const r = await bridge.call<{ status: string; preview: Preview }>('/food/log/delete', { date: args.date, log_ids: args.log_ids, dry_run: dryRun });
				const lines = (r.preview.entries ?? []).map(e => `- ${e.name ?? 'entry'} (${mealLabel(e.meal)})`).join('\n');
				if (r.status === 'preview') return text(`**Remove from ${args.date}:**\n${lines}${PREVIEW_FOOTER}`);
				const after = await refreshDay(bridge, store, args.date);
				return text(`✅ Removed ${r.preview.entries?.length ?? 0} entr${(r.preview.entries?.length ?? 0) === 1 ? 'y' : 'ies'} from ${args.date}.\n\n${renderDay(after)}`);
			}

			case 'garmin_food_copy_day': {
				if (typeof args.from_date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(args.from_date)) return text('from_date (YYYY-MM-DD) is required.', true);
				const to = day(args.to_date);
				const r = await bridge.call<{ status: string; preview: Preview }>('/food/copy_day', { from_date: args.from_date, to_date: to, meals: args.meals, dry_run: dryRun });
				const entries = r.preview.entries ?? [];
				const total = entries.reduce((s, e) => s + (isNum(e.kcal) ? e.kcal : 0), 0);
				const lines = entries.map(e => `- ${mealLabel(e.meal)}: ${e.name} × ${n1(e.servings)} — ${n0(e.kcal)} kcal`).join('\n');
				if (r.status === 'preview') return text(`**Copy ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'} (${n0(total)} kcal) from ${args.from_date} to ${to}:**\n${lines}${PREVIEW_FOOTER}`);
				const after = await refreshDay(bridge, store, to);
				return text(`✅ Copied ${entries.length} entries from ${args.from_date} to ${to}.\n\n${renderDay(after)}`);
			}

			default:
				return text(`Unknown Garmin nutrition tool: ${name}`, true);
		}
	} catch (err) {
		if (err instanceof GarminBridgeError) {
			if (err.status === 401) return text(`Garmin session expired — reconnect at ${reauth}, then try again.`, true);
			if (err.status === 403 || err.status === 402 || /API Error 40[23]\b/.test(err.message)) return text(`Garmin refused the nutrition request (${err.message}). Food logging needs an active Connect+ subscription with nutrition switched on.`, true);
			return text(err.message, true);
		}
		throw err;
	}
}
