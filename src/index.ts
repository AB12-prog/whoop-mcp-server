import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema, ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { timingSafeEqual } from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type Request, type Response } from 'express';
import { WhoopClient, WhoopAuthError } from './whoop-client.js';
import { WhoopDatabase } from './database.js';
import { WhoopSync } from './sync.js';
import { mountOAuthProxy, LoginError, type LoginProvider } from './oauth-proxy.js';
import { GarminBridge, GarminBridgeError, GarminStore, GarminSync, type GarminAccount } from './garmin.js';
import { garminToolDefs, GARMIN_TOOL_NAMES, handleGarminTool } from './garmin-tools.js';
import { garminWriteToolDefs, GARMIN_WRITE_TOOL_NAMES, handleGarminWriteTool } from './garmin-write-tools.js';
import { garminNutritionToolDefs, GARMIN_NUTRITION_TOOL_NAMES, handleGarminNutritionTool } from './garmin-nutrition-tools.js';

interface ToolArguments {
	days?: number;
	full?: boolean;
}

const config = {
	clientId: process.env.WHOOP_CLIENT_ID ?? '',
	clientSecret: process.env.WHOOP_CLIENT_SECRET ?? '',
	redirectUri: process.env.WHOOP_REDIRECT_URI ?? 'http://localhost:3000/callback',
	dbPath: process.env.DB_PATH ?? './whoop.db',
	port: Number.parseInt(process.env.PORT ?? '3000', 10),
	mode: process.env.MCP_MODE ?? 'http',
	// WHOOP is a read-only archive. Set WHOOP_SYNC=on to resume automatic WHOOP
	// pulls (e.g. while a membership is still active); whoop_sync always works
	// manually as long as the stored WHOOP grant is alive.
	whoopAutoSync: (process.env.WHOOP_SYNC ?? 'off').toLowerCase() === 'on',
	baseUrl: (process.env.BASE_URL ?? '').replace(/\/+$/, ''),
};

const db = new WhoopDatabase(config.dbPath);
const client = new WhoopClient({
	clientId: config.clientId,
	clientSecret: config.clientSecret,
	redirectUri: config.redirectUri,
	onTokenRefresh: tokens => db.saveTokens(tokens),
	loadTokens: () => db.getTokens(),
});

const existingTokens = db.getTokens();
if (existingTokens) {
	client.setTokens(existingTokens);
}

const sync = new WhoopSync(client, db);

// ---- Garmin --------------------------------------------------------------

const here = path.dirname(fileURLToPath(import.meta.url));
const garminStore = new GarminStore(config.dbPath);
const garminBridge = new GarminBridge({
	python: process.env.GARMIN_PYTHON ?? (existsSync('/opt/garmin/bin/python') ? '/opt/garmin/bin/python' : 'python3'),
	script: process.env.GARMIN_BRIDGE_PATH ?? path.resolve(here, '..', 'garmin', 'bridge.py'),
	onTokens: tokens => garminStore.saveTokens(tokens),
	loadTokens: () => garminStore.getTokens(),
});
const garminSync = new GarminSync(garminBridge, garminStore);

// Which Garmin account may own this server: an explicit profile id, else the
// account already bound, else (first sign-in only) the owner's email. With none
// of these configured, sign-in fails closed rather than binding to whoever
// reaches the page first.
function expectedGarminProfileId(): number | null {
	const env = Number.parseInt(process.env.GARMIN_ALLOWED_PROFILE_ID ?? '', 10);
	if (Number.isFinite(env)) return env;
	return garminStore.getAccount()?.profile_id ?? null;
}

function checkOwnerEmail(email: string): void {
	const ownerEmail = (process.env.GARMIN_OWNER_EMAIL ?? '').trim().toLowerCase();
	if (expectedGarminProfileId() != null) {
		// Already bound: the bridge enforces the profile id. The email check
		// still applies if configured, as a cheap early reject.
		if (ownerEmail && email.toLowerCase() !== ownerEmail) throw new LoginError("That Garmin account isn't the one this server belongs to.");
		return;
	}
	if (!ownerEmail) {
		throw new LoginError('Server not set up yet: set GARMIN_OWNER_EMAIL in Railway, redeploy, then sign in.');
	}
	if (email.toLowerCase() !== ownerEmail) throw new LoginError("That Garmin account isn't the one this server belongs to.");
}

function garminLoginError(err: unknown): never {
	if (err instanceof LoginError) throw err;
	if (err instanceof GarminBridgeError) {
		const messages: Record<string, string> = {
			auth: "Garmin didn't accept that email and password.",
			wrong_account: "That Garmin account isn't the one this server belongs to.",
			bad_code: "That code didn't work. Check it and try again.",
			expired: 'That sign-in expired. Start again.',
			rate_limited: 'Garmin is limiting sign-ins right now. Wait a few minutes and try again.',
		};
		console.error('[garmin] sign-in failed:', err.code, err.message);
		throw new LoginError(messages[err.code] ?? "Couldn't reach Garmin. Try again shortly.");
	}
	throw err;
}

function onGarminSignedIn(account: GarminAccount | undefined): void {
	if (account && garminStore.getAccount() == null) {
		garminStore.bindAccount(account);
		console.log('[garmin] server bound to Garmin profile', account.profile_id);
	}
	// Pull recent data straight away so the first questions have answers.
	garminSync.smartSync().catch(e => console.error('[garmin] post-login sync failed:', e instanceof Error ? e.message : e));
}

const garminLogin: LoginProvider = {
	async login(email, password) {
		checkOwnerEmail(email);
		try {
			const res = await garminBridge.call<{ status: string; pending_id?: string; account?: GarminAccount }>(
				'/login',
				{ email, password, expected_profile_id: expectedGarminProfileId() },
				180_000
			);
			if (res.status === 'mfa_required' && res.pending_id) return { status: 'mfa_required', pendingId: res.pending_id };
			onGarminSignedIn(res.account);
			return { status: 'ok' };
		} catch (err) {
			garminLoginError(err);
		}
	},
	async verifyMfa(pendingId, code) {
		try {
			const res = await garminBridge.call<{ account?: GarminAccount }>('/login/mfa', { pending_id: pendingId, code }, 120_000);
			onGarminSignedIn(res.account);
		} catch (err) {
			garminLoginError(err);
		}
	},
};

const SESSION_TTL_MS = 30 * 60 * 1000;
const transports = new Map<string, { transport: StreamableHTTPServerTransport; lastAccess: number }>();

function cleanupStaleSessions(): void {
	const now = Date.now();
	for (const [sessionId, session] of transports) {
		if (now - session.lastAccess > SESSION_TTL_MS) {
			session.transport.close().catch(() => {});
			transports.delete(sessionId);
		}
	}
}

setInterval(cleanupStaleSessions, 5 * 60 * 1000);

function formatDuration(millis: number | null): string {
	if (millis == null || Number.isNaN(millis)) return 'N/A';
	const hours = Math.floor(millis / 3_600_000);
	const minutes = Math.floor((millis % 3_600_000) / 60_000);
	return `${hours}h ${minutes}m`;
}

function formatDate(isoString: string): string {
	return new Date(isoString).toLocaleDateString('en-US', {
		weekday: 'short',
		month: 'short',
		day: 'numeric',
	});
}

function getRecoveryZone(score: number): string {
	if (score >= 67) return 'Green (Well Recovered)';
	if (score >= 34) return 'Yellow (Moderate)';
	return 'Red (Needs Rest)';
}

function getStrainZone(strain: number): string {
	if (strain >= 18) return 'All Out (18-21)';
	if (strain >= 14) return 'High (14-17)';
	if (strain >= 10) return 'Moderate (10-13)';
	return 'Light (0-9)';
}

function validateDays(value: unknown): number {
	if (value === undefined || value === null) return 14;
	const num = typeof value === 'number' ? value : Number.parseInt(String(value), 10);
	if (Number.isNaN(num) || num < 1) return 14;
	return Math.min(num, 3650);
}

function validateBoolean(value: unknown): boolean {
	if (typeof value === 'boolean') return value;
	if (value === 'true') return true;
	return false;
}

const ARCHIVE_NOTE = 'WHOOP archive (read-only; WHOOP was worn until late Sep 2026 — use the garmin_* tools for current data).';

function createMcpServer(): Server {
	const server = new Server(
		{ name: 'health-mcp-server', version: '2.0.0' },
		{ capabilities: { tools: {} } }
	);

	const daysProp = { days: { type: 'number', description: 'Days back from today (default: 14, max: 3650)' } };

	server.setRequestHandler(ListToolsRequestSchema, async () => ({
		tools: [
			...garminToolDefs,
			...garminWriteToolDefs,
			...garminNutritionToolDefs,
			{
				name: 'whoop_latest',
				description: `${ARCHIVE_NOTE} Last recorded WHOOP recovery, sleep and strain.`,
				inputSchema: { type: 'object', properties: {}, required: [] },
			},
			{
				name: 'whoop_recovery_trends',
				description: `${ARCHIVE_NOTE} Recovery score, HRV and resting HR by day.`,
				inputSchema: { type: 'object', properties: daysProp, required: [] },
			},
			{
				name: 'whoop_sleep_analysis',
				description: `${ARCHIVE_NOTE} Sleep duration, performance and efficiency by night.`,
				inputSchema: { type: 'object', properties: daysProp, required: [] },
			},
			{
				name: 'whoop_strain_history',
				description: `${ARCHIVE_NOTE} Daily strain and calories.`,
				inputSchema: { type: 'object', properties: daysProp, required: [] },
			},
			{
				name: 'whoop_records',
				description: `${ARCHIVE_NOTE} Full raw WHOOP records as JSON (sleep stages, SpO2, skin temp, respiratory rate, sleep debt, disturbances, workout HR zones).`,
				inputSchema: {
					type: 'object',
					properties: {
						type: { type: 'string', enum: ['recovery', 'sleep', 'cycles', 'workouts'], description: 'Which data type to return.' },
						days: { type: 'number', description: 'How many days back from today (default: 14, max: 3650).' },
						limit: { type: 'number', description: 'Max records to return, most recent first (default: 500, max: 2000).' },
					},
					required: ['type'],
				},
			},
			{
				name: 'whoop_profile',
				description: `${ARCHIVE_NOTE} Stored WHOOP profile and last body measurement (height, weight, max HR).`,
				inputSchema: { type: 'object', properties: {}, required: [] },
			},
			{
				name: 'whoop_sync',
				description: 'Pull any remaining data from WHOOP into the archive while the WHOOP grant still works. full=true re-pulls the entire history.',
				inputSchema: {
					type: 'object',
					properties: { full: { type: 'boolean', description: 'Re-pull the entire WHOOP history (default: false)' } },
					required: [],
				},
			},
		],
	}));

	server.setRequestHandler(CallToolRequestSchema, async request => {
		const { name, arguments: args } = request.params;
		const typedArgs = (args ?? {}) as ToolArguments;

		try {
			if (GARMIN_WRITE_TOOL_NAMES.has(name)) {
				return await handleGarminWriteTool(name, (args ?? {}) as Record<string, unknown>, {
					bridge: garminBridge,
					sync: garminSync,
					baseUrl: config.baseUrl,
				});
			}

			if (GARMIN_NUTRITION_TOOL_NAMES.has(name)) {
				return await handleGarminNutritionTool(name, (args ?? {}) as Record<string, unknown>, {
					bridge: garminBridge,
					store: garminStore,
					sync: garminSync,
					baseUrl: config.baseUrl,
				});
			}

			if (GARMIN_TOOL_NAMES.has(name)) {
				return await handleGarminTool(name, (args ?? {}) as Record<string, unknown>, {
					store: garminStore,
					sync: garminSync,
					baseUrl: config.baseUrl,
				});
			}

			// Archive reads serve stored data. Only when WHOOP_SYNC=on do they
			// refresh from WHOOP first (a lapsed membership would just error).
			const archiveReads = ['whoop_latest', 'whoop_recovery_trends', 'whoop_sleep_analysis', 'whoop_strain_history', 'whoop_records'];
			if (config.whoopAutoSync && archiveReads.includes(name)) {
				const tokens = db.getTokens();
				if (tokens) {
					client.setTokens(tokens);
					try {
						await sync.smartSync();
					} catch (err) {
						console.error('[whoop] pre-tool sync failed; serving archive:', err instanceof Error ? err.message : err);
					}
				}
			}

			switch (name) {
				case 'whoop_latest': {
					const recovery = db.getLatestRecovery();
					const sleep = db.getLatestSleep();
					const cycle = db.getLatestCycle();

					if (!recovery && !sleep && !cycle) {
						return { content: [{ type: 'text', text: 'The WHOOP archive is empty.' }] };
					}

					let response = '# Latest WHOOP data (archive)\n\n';

					if (recovery) {
						response += `## Recovery (${formatDate(recovery.created_at)}): ${recovery.recovery_score ?? 'N/A'}% ${recovery.recovery_score ? getRecoveryZone(recovery.recovery_score) : ''}\n`;
						response += `- **HRV**: ${recovery.hrv_rmssd?.toFixed(1) ?? 'N/A'} ms\n`;
						response += `- **Resting HR**: ${recovery.resting_hr ?? 'N/A'} bpm\n`;
						if (recovery.spo2) response += `- **SpO2**: ${recovery.spo2.toFixed(1)}%\n`;
						if (recovery.skin_temp) response += `- **Skin Temp**: ${recovery.skin_temp.toFixed(1)}°C\n`;
						response += '\n';
					}

					if (sleep) {
						const totalSleep = (sleep.total_in_bed_milli ?? 0) - (sleep.total_awake_milli ?? 0);
						response += `## Sleep (${formatDate(sleep.start_time)})\n`;
						response += `- **Total Sleep**: ${formatDuration(totalSleep)}\n`;
						response += `- **Performance**: ${sleep.sleep_performance?.toFixed(0) ?? 'N/A'}%\n`;
						response += `- **Efficiency**: ${sleep.sleep_efficiency?.toFixed(0) ?? 'N/A'}%\n`;
						response += `- **Stages**: Light ${formatDuration(sleep.total_light_milli)}, Deep ${formatDuration(sleep.total_deep_milli)}, REM ${formatDuration(sleep.total_rem_milli)}\n`;
						if (sleep.respiratory_rate) response += `- **Respiratory Rate**: ${sleep.respiratory_rate.toFixed(1)} breaths/min\n`;
						response += '\n';
					}

					if (cycle) {
						response += `## Strain (${formatDate(cycle.start_time)})\n`;
						response += `- **Day Strain**: ${cycle.strain?.toFixed(1) ?? 'N/A'} ${cycle.strain ? getStrainZone(cycle.strain) : ''}\n`;
						if (cycle.kilojoule) response += `- **Calories**: ${Math.round(cycle.kilojoule / 4.184)} kcal\n`;
					}

					return { content: [{ type: 'text', text: response }] };
				}

				case 'whoop_recovery_trends': {
					const days = validateDays(typedArgs.days);
					const trends = db.getRecoveryTrends(days);

					if (trends.length === 0) {
						return { content: [{ type: 'text', text: 'No WHOOP recovery data in that window.' }] };
					}

					let response = `# WHOOP Recovery (archive, last ${days} days)\n\n`;
					response += '| Date | Recovery | HRV | RHR |\n|------|----------|-----|-----|\n';

					for (const day of trends) {
						response += `| ${formatDate(day.date)} | ${day.recovery_score}% | ${day.hrv?.toFixed(1) ?? 'N/A'} ms | ${day.rhr ?? 'N/A'} bpm |\n`;
					}

					const avgRecovery = trends.reduce((sum, d) => sum + (d.recovery_score || 0), 0) / trends.length;
					const avgHrv = trends.reduce((sum, d) => sum + (d.hrv || 0), 0) / trends.length;
					const avgRhr = trends.reduce((sum, d) => sum + (d.rhr || 0), 0) / trends.length;

					response += `\n## Averages\n- **Recovery**: ${avgRecovery.toFixed(0)}%\n- **HRV**: ${avgHrv.toFixed(1)} ms\n- **RHR**: ${avgRhr.toFixed(0)} bpm\n`;

					return { content: [{ type: 'text', text: response }] };
				}

				case 'whoop_sleep_analysis': {
					const days = validateDays(typedArgs.days);
					const trends = db.getSleepTrends(days);

					if (trends.length === 0) {
						return { content: [{ type: 'text', text: 'No WHOOP sleep data in that window.' }] };
					}

					let response = `# WHOOP Sleep (archive, last ${days} days)\n\n`;
					response += '| Date | Duration | Performance | Efficiency |\n|------|----------|-------------|------------|\n';

					for (const day of trends) {
						response += `| ${formatDate(day.date)} | ${day.total_sleep_hours?.toFixed(1) ?? 'N/A'}h | ${day.performance?.toFixed(0) ?? 'N/A'}% | ${day.efficiency?.toFixed(0) ?? 'N/A'}% |\n`;
					}

					const avgDuration = trends.reduce((sum, d) => sum + (d.total_sleep_hours || 0), 0) / trends.length;
					const avgPerf = trends.reduce((sum, d) => sum + (d.performance || 0), 0) / trends.length;
					const avgEff = trends.reduce((sum, d) => sum + (d.efficiency || 0), 0) / trends.length;

					response += `\n## Averages\n- **Duration**: ${avgDuration.toFixed(1)} hours\n- **Performance**: ${avgPerf.toFixed(0)}%\n- **Efficiency**: ${avgEff.toFixed(0)}%\n`;

					return { content: [{ type: 'text', text: response }] };
				}

				case 'whoop_strain_history': {
					const days = validateDays(typedArgs.days);
					const trends = db.getStrainTrends(days);

					if (trends.length === 0) {
						return { content: [{ type: 'text', text: 'No WHOOP strain data in that window.' }] };
					}

					let response = `# WHOOP Strain (archive, last ${days} days)\n\n`;
					response += '| Date | Strain | Calories |\n|------|--------|----------|\n';

					for (const day of trends) {
						response += `| ${formatDate(day.date)} | ${day.strain?.toFixed(1) ?? 'N/A'} | ${day.calories ?? 'N/A'} kcal |\n`;
					}

					const avgStrain = trends.reduce((sum, d) => sum + (d.strain || 0), 0) / trends.length;
					const avgCalories = trends.reduce((sum, d) => sum + (d.calories || 0), 0) / trends.length;

					response += `\n## Averages\n- **Daily Strain**: ${avgStrain.toFixed(1)}\n- **Daily Calories**: ${Math.round(avgCalories)} kcal\n`;

					return { content: [{ type: 'text', text: response }] };
				}

				case 'whoop_sync': {
					const tokens = db.getTokens();
					if (!tokens) {
						return { content: [{ type: 'text', text: 'No WHOOP grant stored, so nothing more can be pulled. The archive is still readable.' }] };
					}
					client.setTokens(tokens);

					if (validateBoolean(typedArgs.full)) {
						// A full backfill pages through the entire account and can take a
						// few minutes, so run it in the background and return right away.
						sync.syncAll()
							.then(s => console.log('[whoop] full backfill complete', s))
							.catch(e => console.error('[whoop] full backfill failed', e instanceof Error ? e.message : e));
						return { content: [{ type: 'text', text: 'Full WHOOP re-pull started in the background (a couple of minutes).' }] };
					}

					const stats = await sync.quickSync();
					return {
						content: [{
							type: 'text',
							text: `WHOOP sync complete (last 7 days):\n- Cycles: ${stats.cycles}\n- Recoveries: ${stats.recoveries}\n- Sleeps: ${stats.sleeps}\n- Workouts: ${stats.workouts}`,
						}],
					};
				}

				case 'whoop_records': {
					const type = String((typedArgs as { type?: string }).type ?? '');
					const days = validateDays(typedArgs.days);
					const rawLimit = (typedArgs as { limit?: number }).limit;
					const limit = Math.min(Math.max(Number.parseInt(String(rawLimit ?? 500), 10) || 500, 1), 2000);

					const end = new Date();
					const start = new Date();
					start.setDate(start.getDate() - days);
					const startIso = start.toISOString();
					const endIso = end.toISOString();

					let rows: Array<Record<string, unknown>>;
					switch (type) {
						case 'recovery':
							rows = db.getRecoveriesByDateRange(startIso, endIso) as unknown as Array<Record<string, unknown>>;
							break;
						case 'sleep':
							rows = db.getSleepsByDateRange(startIso, endIso, true) as unknown as Array<Record<string, unknown>>;
							break;
						case 'cycles':
							rows = db.getCyclesByDateRange(startIso, endIso) as unknown as Array<Record<string, unknown>>;
							break;
						case 'workouts':
							rows = db.getWorkoutsByDateRange(startIso, endIso) as unknown as Array<Record<string, unknown>>;
							break;
						default:
							return { content: [{ type: 'text', text: 'Invalid type. Use one of: recovery, sleep, cycles, workouts.' }] };
					}

					const total = rows.length;
					const truncated = total > limit;
					const out = truncated ? rows.slice(0, limit) : rows;
					return { content: [{ type: 'text', text: JSON.stringify({ type, days, returned: out.length, total_in_window: total, truncated, records: out }) }] };
				}

				case 'whoop_profile': {
					const profile = db.getProfile();
					const body = db.getBodyMeasurement();
					if (!profile && !body) {
						return { content: [{ type: 'text', text: 'No WHOOP profile stored.' }] };
					}
					return { content: [{ type: 'text', text: JSON.stringify({ profile, body_measurement: body }) }] };
				}

				default:
					throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
			}
		} catch (error) {
			const message = error instanceof Error ? error.message : 'Unknown error';
			return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
		}
	});

	return server;
}

async function main(): Promise<void> {
	if (config.mode === 'stdio') {
		const server = createMcpServer();
		const transport = new StdioServerTransport();
		await server.connect(transport);
		process.stderr.write('Health MCP server running on stdio\n');
	} else {
		const app = express();
		app.use(express.json());
		app.use(express.urlencoded({ extended: true }));

		const baseUrl = (process.env.BASE_URL ?? '').replace(/\/+$/, '');
		if (!baseUrl) {
			throw new Error('BASE_URL env var is required, e.g. https://your-app.up.railway.app');
		}

		const { requireMcpAuth } = mountOAuthProxy({
			app,
			dbPath: config.dbPath,
			baseUrl,
			loginProvider: garminLogin,
		});

		// Start the Garmin sidecar now so the first tool call doesn't pay for it.
		garminBridge.warmUp();

		app.get('/health', (_req: Request, res: Response) => {
			const garminState = garminStore.getSyncState();
			const account = garminStore.getAccount();
			res.json({
				status: 'ok',
				garmin: {
					connected: garminSync.isConnected(),
					bound: Boolean(account),
					tokens_updated_at: account?.tokens_updated_at ?? null,
					last_sync_at: garminState.last_sync_at,
					stored_range: [garminState.oldest_date, garminState.newest_date],
					last_error: garminState.last_error,
				},
				whoop: {
					mode: config.whoopAutoSync ? 'syncing' : 'archive',
					grant_stored: Boolean(db.getTokens()),
					token_updated_at: db.getTokenUpdatedAt(),
				},
			});
		});

		// Scheduled-sync endpoint: the Railway cron service pings this hourly.
		// smartSync already skips if it synced <1h ago, so dashboard opens and
		// cron runs never double-pull.
		app.post('/sync', async (req: Request, res: Response) => {
			// Fail closed if SYNC_SECRET isn't configured — a strict !== against an
			// unset env var would let a missing header through. Compare in constant
			// time so the secret can't be recovered byte-by-byte.
			const secret = process.env.SYNC_SECRET ?? '';
			const provided = req.header('x-sync-secret') ?? '';
			const secretBuf = Buffer.from(secret);
			const providedBuf = Buffer.from(provided);
			const authorized =
				secret.length > 0 &&
				secretBuf.length === providedBuf.length &&
				timingSafeEqual(secretBuf, providedBuf);
			if (!authorized) {
				res.status(401).json({ error: 'unauthorized' });
				return;
			}

			// Put the real reason in the response: the cron runner prints the
			// body, so its logs say what broke instead of a bare "sync failed".
			const result: Record<string, unknown> = {};
			let ok = true;
			let status = 200;

			if (garminSync.backfillStatus().running) {
				result.garmin = { type: 'skip', reason: 'backfill running' };
			} else {
				try {
					result.garmin = await garminSync.smartSync();
				} catch (err) {
					ok = false;
					const detail = err instanceof Error ? err.message : String(err);
					console.error('[sync] garmin error', detail);
					if (err instanceof GarminBridgeError && err.status === 401) {
						status = 401;
						result.garmin = { error: 'garmin session expired', detail, action: `sign in at ${baseUrl}/reauth` };
					} else {
						status = 500;
						result.garmin = { error: 'garmin sync failed', detail };
					}
				}
			}

			if (config.whoopAutoSync) {
				try {
					result.whoop = await sync.smartSync();
				} catch (err) {
					// WHOOP is secondary now; report it without failing the run.
					const detail = err instanceof Error ? err.message : String(err);
					console.error('[sync] whoop error', detail);
					result.whoop = { error: err instanceof WhoopAuthError ? 'whoop auth expired' : 'whoop sync failed', detail };
				}
			}

			res.status(status).json({ ok, ...result });
		});

		app.all('/mcp', requireMcpAuth, async (req: Request, res: Response) => {
			const sessionId = req.headers['mcp-session-id'] as string | undefined;

			// A presented session id we don't recognize means the session is gone —
			// a restart cleared the in-memory map, or the idle TTL reaped it. The
			// MCP streamable-HTTP spec says to answer 404 so the client silently
			// re-initializes. The previous behavior (handing the request to a fresh
			// uninitialized transport) produced a 400 "server not initialized" that
			// clients don't recover from, leaving every connected client broken
			// after each deploy until it was manually reconnected.
			if (sessionId && !transports.has(sessionId)) {
				res.status(404).json({
					jsonrpc: '2.0',
					error: { code: -32001, message: 'Session not found' },
					id: null,
				});
				return;
			}

			if (req.method === 'DELETE' && sessionId && transports.has(sessionId)) {
				const session = transports.get(sessionId)!;
				await session.transport.close();
				transports.delete(sessionId);
				res.status(200).send('Session closed');
				return;
			}

			if (req.method === 'POST') {
				let transport: StreamableHTTPServerTransport;

				if (sessionId && transports.has(sessionId)) {
					const session = transports.get(sessionId)!;
					session.lastAccess = Date.now();
					transport = session.transport;
				} else {
					transport = new StreamableHTTPServerTransport({
						sessionIdGenerator: () => crypto.randomUUID(),
						onsessioninitialized: newSessionId => {
							transports.set(newSessionId, { transport, lastAccess: Date.now() });
						},
					});

					const server = createMcpServer();
					await server.connect(transport);
				}

				try {
					await transport.handleRequest(req, res, req.body);
				} catch (err) {
					console.error('[mcp] handleRequest error', err);
					if (!res.headersSent) {
						res.status(500).json({ error: 'internal_error' });
					}
				}
				return;
			}

			res.status(405).send('Method not allowed');
		});

		app.get('/sse', (_req: Request, res: Response) => {
			res.status(410).send('SSE endpoint deprecated. Use /mcp with Streamable HTTP transport.');
		});

		const server = app.listen(config.port, '0.0.0.0', () => {
			process.stdout.write(`Health MCP server running on http://0.0.0.0:${config.port}\n`);
		});

		const shutdown = (): void => {
			process.stdout.write('\nShutting down...\n');
			for (const [, session] of transports) {
				session.transport.close().catch(() => {});
			}
			transports.clear();
			garminBridge.stop();
			garminStore.close();
			db.close();
			server.close(() => process.exit(0));
		};

		process.on('SIGTERM', shutdown);
		process.on('SIGINT', shutdown);
	}
}

main().catch(error => {
	process.stderr.write(`Fatal error: ${error}\n`);
	process.exit(1);
});
