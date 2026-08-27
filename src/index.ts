import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema, ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { timingSafeEqual } from 'node:crypto';
import express, { type Request, type Response } from 'express';
import { WhoopClient, WhoopAuthError } from './whoop-client.js';
import { WhoopDatabase } from './database.js';
import { WhoopSync } from './sync.js';
import { mountOAuthProxy } from './oauth-proxy.js';

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

function createMcpServer(): Server {
	const server = new Server(
		{ name: 'whoop-mcp-server', version: '1.0.0' },
		{ capabilities: { tools: {} } }
	);

	server.setRequestHandler(ListToolsRequestSchema, async () => ({
		tools: [
			{
				name: 'get_today',
				description: "Get today's Whoop data including recovery score, last night's sleep, and current strain.",
				inputSchema: { type: 'object', properties: {}, required: [] },
			},
			{
				name: 'get_recovery_trends',
				description: 'Get recovery score trends over time, including HRV and resting heart rate patterns.',
				inputSchema: {
					type: 'object',
					properties: { days: { type: 'number', description: 'Number of days to analyze (default: 14, max: 3650)' } },
					required: [],
				},
			},
			{
				name: 'get_sleep_analysis',
				description: 'Get detailed sleep analysis including duration, stages, efficiency, and sleep debt.',
				inputSchema: {
					type: 'object',
					properties: { days: { type: 'number', description: 'Number of days to analyze (default: 14, max: 3650)' } },
					required: [],
				},
			},
			{
				name: 'get_strain_history',
				description: 'Get training strain history and workout data.',
				inputSchema: {
					type: 'object',
					properties: { days: { type: 'number', description: 'Number of days to analyze (default: 14, max: 3650)' } },
					required: [],
				},
			},
			{
				name: 'sync_data',
				description: 'Manually trigger a data sync from Whoop.',
				inputSchema: {
					type: 'object',
					properties: { full: { type: 'boolean', description: 'Run a full historical backfill of your entire WHOOP account, as far back as the data goes (default: false)' } },
					required: [],
				},
			},
			{
				name: 'get_records',
				description: 'Return full raw records (every stored field) for a data type over a time window, as JSON, for detailed analysis. Use this instead of the summary tools when you need fields like sleep stages, SpO2, skin temp, respiratory rate, sleep debt, disturbances, or workout HR-zone durations.',
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
				name: 'get_profile',
				description: "Return the user's WHOOP profile (name, email) and latest body measurement (height, weight, max heart rate).",
				inputSchema: { type: 'object', properties: {}, required: [] },
			},
			{
				name: 'get_auth_url',
				description: 'Get the Whoop authorization URL to connect your account.',
				inputSchema: { type: 'object', properties: {}, required: [] },
			},
		],
	}));

	server.setRequestHandler(CallToolRequestSchema, async request => {
		const { name, arguments: args } = request.params;
		const typedArgs = (args ?? {}) as ToolArguments;

		try {
			const dataTools = ['get_today', 'get_recovery_trends', 'get_sleep_analysis', 'get_strain_history'];
			if (dataTools.includes(name)) {
				const tokens = db.getTokens();
				if (!tokens) {
					return { content: [{ type: 'text', text: 'Not authenticated with Whoop. Use get_auth_url to authorize first.' }] };
				}
				client.setTokens(tokens);
				try {
					await sync.smartSync();
				} catch (err) {
					// Continue with cached data, but leave a trace — silent failures
					// here previously hid a dying WHOOP grant for a whole day.
					console.error('[sync] pre-tool sync failed; serving cached data:', err instanceof Error ? err.message : err);
				}
			}

			switch (name) {
				case 'get_today': {
					const recovery = db.getLatestRecovery();
					const sleep = db.getLatestSleep();
					const cycle = db.getLatestCycle();

					if (!recovery && !sleep && !cycle) {
						return { content: [{ type: 'text', text: 'No data available. Try running sync_data first.' }] };
					}

					let response = "# Today's Whoop Summary\n\n";

					if (recovery) {
						response += `## Recovery: ${recovery.recovery_score ?? 'N/A'}% ${recovery.recovery_score ? getRecoveryZone(recovery.recovery_score) : ''}\n`;
						response += `- **HRV**: ${recovery.hrv_rmssd?.toFixed(1) ?? 'N/A'} ms\n`;
						response += `- **Resting HR**: ${recovery.resting_hr ?? 'N/A'} bpm\n`;
						if (recovery.spo2) response += `- **SpO2**: ${recovery.spo2.toFixed(1)}%\n`;
						if (recovery.skin_temp) response += `- **Skin Temp**: ${recovery.skin_temp.toFixed(1)}°C\n`;
						response += '\n';
					}

					if (sleep) {
						const totalSleep = (sleep.total_in_bed_milli ?? 0) - (sleep.total_awake_milli ?? 0);
						response += `## Last Night's Sleep\n`;
						response += `- **Total Sleep**: ${formatDuration(totalSleep)}\n`;
						response += `- **Performance**: ${sleep.sleep_performance?.toFixed(0) ?? 'N/A'}%\n`;
						response += `- **Efficiency**: ${sleep.sleep_efficiency?.toFixed(0) ?? 'N/A'}%\n`;
						response += `- **Stages**: Light ${formatDuration(sleep.total_light_milli)}, Deep ${formatDuration(sleep.total_deep_milli)}, REM ${formatDuration(sleep.total_rem_milli)}\n`;
						if (sleep.respiratory_rate) response += `- **Respiratory Rate**: ${sleep.respiratory_rate.toFixed(1)} breaths/min\n`;
						response += '\n';
					}

					if (cycle) {
						response += `## Current Strain\n`;
						response += `- **Day Strain**: ${cycle.strain?.toFixed(1) ?? 'N/A'} ${cycle.strain ? getStrainZone(cycle.strain) : ''}\n`;
						if (cycle.kilojoule) response += `- **Calories**: ${Math.round(cycle.kilojoule / 4.184)} kcal\n`;
						if (cycle.avg_hr) response += `- **Avg HR**: ${cycle.avg_hr} bpm\n`;
						if (cycle.max_hr) response += `- **Max HR**: ${cycle.max_hr} bpm\n`;
					}

					return { content: [{ type: 'text', text: response }] };
				}

				case 'get_recovery_trends': {
					const days = validateDays(typedArgs.days);
					const trends = db.getRecoveryTrends(days);

					if (trends.length === 0) {
						return { content: [{ type: 'text', text: 'No recovery data available for the requested period.' }] };
					}

					let response = `# Recovery Trends (Last ${days} Days)\n\n`;
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

				case 'get_sleep_analysis': {
					const days = validateDays(typedArgs.days);
					const trends = db.getSleepTrends(days);

					if (trends.length === 0) {
						return { content: [{ type: 'text', text: 'No sleep data available for the requested period.' }] };
					}

					let response = `# Sleep Analysis (Last ${days} Days)\n\n`;
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

				case 'get_strain_history': {
					const days = validateDays(typedArgs.days);
					const trends = db.getStrainTrends(days);

					if (trends.length === 0) {
						return { content: [{ type: 'text', text: 'No strain data available for the requested period.' }] };
					}

					let response = `# Strain History (Last ${days} Days)\n\n`;
					response += '| Date | Strain | Calories |\n|------|--------|----------|\n';

					for (const day of trends) {
						response += `| ${formatDate(day.date)} | ${day.strain?.toFixed(1) ?? 'N/A'} | ${day.calories ?? 'N/A'} kcal |\n`;
					}

					const avgStrain = trends.reduce((sum, d) => sum + (d.strain || 0), 0) / trends.length;
					const avgCalories = trends.reduce((sum, d) => sum + (d.calories || 0), 0) / trends.length;

					response += `\n## Averages\n- **Daily Strain**: ${avgStrain.toFixed(1)}\n- **Daily Calories**: ${Math.round(avgCalories)} kcal\n`;

					return { content: [{ type: 'text', text: response }] };
				}

				case 'sync_data': {
					const tokens = db.getTokens();
					if (!tokens) {
						return { content: [{ type: 'text', text: 'Not authenticated with Whoop. Connect the Whoop connector first.' }] };
					}
					client.setTokens(tokens);

					const full = validateBoolean(typedArgs.full);

					if (full) {
						// A full backfill pages through the entire account and can take a
						// few minutes, so run it in the background and return right away
						// rather than holding the tool call open until it times out.
						sync.syncAll()
							.then(s => console.log('[sync] full backfill complete', s))
							.catch(e => console.error('[sync] full backfill failed', e instanceof Error ? e.message : e));
						return {
							content: [{
								type: 'text',
								text: 'Full historical backfill started in the background. It pulls your entire WHOOP history and usually takes a couple of minutes. Give it a moment, then ask for whatever you want to look at — once it finishes, queries and analysis cover your full history.',
							}],
						};
					}

					const result = await sync.smartSync();
					if (result.type === 'skip') {
						return { content: [{ type: 'text', text: 'Data is already up to date (synced within the last hour).' }] };
					}
					const stats = result.stats;
					return {
						content: [{
							type: 'text',
							text: `Sync complete!\n- Cycles: ${stats?.cycles}\n- Recoveries: ${stats?.recoveries}\n- Sleeps: ${stats?.sleeps}\n- Workouts: ${stats?.workouts}`,
						}],
					};
				}

				case 'get_records': {
					const tokens = db.getTokens();
					if (!tokens) {
						return { content: [{ type: 'text', text: 'Not authenticated with Whoop. Connect the Whoop connector first.' }] };
					}
					client.setTokens(tokens);
					try {
						await sync.smartSync();
					} catch {
						// Continue with cached data
					}

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
							return { content: [{ type: 'text', text: "Invalid type. Use one of: recovery, sleep, cycles, workouts." }] };
					}

					const total = rows.length;
					const truncated = total > limit;
					const out = truncated ? rows.slice(0, limit) : rows;
					const payload = {
						type,
						days,
						returned: out.length,
						total_in_window: total,
						truncated,
						records: out,
					};
					return { content: [{ type: 'text', text: JSON.stringify(payload) }] };
				}

				case 'get_profile': {
					const tokens = db.getTokens();
					if (!tokens) {
						return { content: [{ type: 'text', text: 'Not authenticated with Whoop. Connect the Whoop connector first.' }] };
					}
					const profile = db.getProfile();
					const body = db.getBodyMeasurement();
					if (!profile && !body) {
						return { content: [{ type: 'text', text: 'No profile or body measurement stored yet. Run sync_data first.' }] };
					}
					return { content: [{ type: 'text', text: JSON.stringify({ profile, body_measurement: body }) }] };
				}

				case 'get_auth_url': {
					// The /reauth flow registers its state in oauth_pending, which
					// /callback requires. A raw getAuthorizationUrl() link can never
					// complete: its state is unknown to /callback and gets rejected.
					const base = (process.env.BASE_URL ?? '').replace(/\/+$/, '');
					if (!base) {
						return {
							content: [{
								type: 'text',
								text: 'BASE_URL is not configured, so no re-authorization URL is available. In HTTP mode, set BASE_URL and visit /reauth on the server.',
							}],
						};
					}
					return {
						content: [{
							type: 'text',
							text: `To (re)authorize WHOOP:\n\n1. Visit: ${base}/reauth\n2. Log in to WHOOP and approve access\n3. You'll see a confirmation once tokens are saved\n\nThis re-links the WHOOP account this server is bound to; scheduled syncs resume immediately after.`,
						}],
					};
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
		process.stderr.write('Whoop MCP server running on stdio\n');
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
			whoopClientId: config.clientId,
			whoopRedirectUri: config.redirectUri,
			exchangeAndSaveWhoopCode: async (code: string) => {
				// Any WHOOP account can complete the proxied login, but this server
				// stores exactly one user's data. Verify the account that just logged
				// in is the account this server is bound to before persisting anything,
				// otherwise a stranger connecting their own WHOOP account would (a)
				// overwrite the owner's tokens and (b) get an MCP token that reads the
				// owner's stored health history.
				const previousTokens = db.getTokens();
				try {
					const tokens = await client.exchangeCodeForTokens(code);
					const profile = await client.getProfile();

					const allowedUserId = (process.env.WHOOP_ALLOWED_USER_ID ?? '').trim();
					const storedProfile = db.getProfile();
					if (allowedUserId && String(profile.user_id) !== allowedUserId) {
						throw new Error(`WHOOP user ${profile.user_id} is not the allowed user for this server`);
					}
					if (!allowedUserId && storedProfile?.user_id != null && storedProfile.user_id !== profile.user_id) {
						throw new Error(`WHOOP user ${profile.user_id} does not match the account this server is bound to`);
					}

					db.saveTokens(tokens);
					db.saveProfile(profile);
					sync.syncDays(90).catch(() => {});
				} catch (err) {
					// Don't leave the rejected login's tokens on the shared client.
					if (previousTokens) {
						client.setTokens(previousTokens);
					} else {
						client.clearTokens();
					}
					throw err;
				}
			},
		});

		app.get('/health', (_req: Request, res: Response) => {
			// token_updated_at is the last successful rotation's save time — if the
			// grant dies, it pins down when the last good refresh happened.
			res.json({
				status: 'ok',
				authenticated: Boolean(db.getTokens()),
				token_updated_at: db.getTokenUpdatedAt(),
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
			try {
				const result = await sync.smartSync();
				res.json({ ok: true, ...result });
			} catch (err) {
				console.error('[sync] error', err);
				const detail = err instanceof Error ? err.message : String(err);
				// Put the real reason in the response: the cron runner prints the
				// body, so its logs say what broke instead of a bare "sync failed".
				if (err instanceof WhoopAuthError) {
					res.status(401).json({
						ok: false,
						error: 'whoop auth expired',
						detail,
						action: `re-authorize at ${baseUrl}/reauth`,
					});
				} else {
					res.status(500).json({ ok: false, error: 'sync failed', detail });
				}
			}
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
			process.stdout.write(`Whoop MCP server running on http://0.0.0.0:${config.port}\n`);
		});

		const shutdown = (): void => {
			process.stdout.write('\nShutting down...\n');
			for (const [, session] of transports) {
				session.transport.close().catch(() => {});
			}
			transports.clear();
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
