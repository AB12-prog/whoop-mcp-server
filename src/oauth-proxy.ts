// src/oauth-proxy.ts
//
// Turns this MCP server into a minimal OAuth 2.1 authorization server that
// Claude.ai's custom connector can authenticate against.
//
// Design: the /authorize step shows a sign-in page served by THIS server where
// the owner signs in with their Garmin Connect account (email, password, and
// Garmin's emailed/app code when MFA is on). Only after Garmin accepts the login
// — and the account is verified to be the one this server is bound to — does
// the server mint a Claude authorization code. Completing Claude's OAuth flow
// therefore also (re)connects Garmin, so one sign-in wires up both sides.
// The Garmin password is relayed straight to Garmin and never stored or logged.
//
// (History: this used to proxy WHOOP's OAuth login. WHOOP is now a read-only
// archive; connector tokens issued under the old flow remain valid.)
//
// Standards notes:
//  - PKCE S256 is required (Claude always sends it).
//  - Dynamic Client Registration (/register) is supported; Claude registers as a
//    public client (token_endpoint_auth_method = "none"), so no client secret.
//  - Authorization codes are single-use and short-lived.
//  - Server-issued access/refresh tokens are stored only as SHA-256 hashes.

import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import type { Express, Request, Response, NextFunction } from 'express';

const SCOPE = 'health:read';

const ACCESS_TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours — fewer refreshes = fewer races with Claude
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const AUTH_CODE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const PENDING_TTL_MS = 10 * 60 * 1000; // 10 minutes — room for an emailed MFA code

// Sign-in attempts are relayed to Garmin, so throttle them hard: this keeps the
// page from being used to hammer Garmin (which would also get the server's IP
// rate-limited) or as a password-guessing oracle.
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_PER_WINDOW = 8;

export type LoginOutcome = { status: 'ok' } | { status: 'mfa_required'; pendingId: string };

/** Error whose message is safe to show on the sign-in page. */
export class LoginError extends Error {}

export interface LoginProvider {
	login(email: string, password: string): Promise<LoginOutcome>;
	verifyMfa(pendingId: string, code: string): Promise<void>;
}

interface OAuthProxyOptions {
	app: Express;
	dbPath: string;
	baseUrl: string; // public https URL of THIS server, no trailing slash
	// Performs the Garmin sign-in (and account binding check). Provided by
	// index.ts so this module stays decoupled from the Garmin bridge.
	loginProvider: LoginProvider;
}

interface OAuthProxy {
	requireMcpAuth: (req: Request, res: Response, next: NextFunction) => void;
}

function sha256hex(input: string): string {
	return crypto.createHash('sha256').update(input).digest('hex');
}

function sha256base64url(input: string): string {
	return crypto.createHash('sha256').update(input).digest('base64url');
}

function randomToken(): string {
	return crypto.randomBytes(32).toString('base64url');
}

// ---- Sign-in pages -----------------------------------------------------------

function escapeHtml(value: string): string {
	return value.replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);
}

function page(title: string, body: string): string {
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>${escapeHtml(title)}</title>
<style>
:root{--bg:#f6f5f2;--card:#fff;--fg:#1d1d1b;--muted:#6b6a66;--line:#dcdad4;--accent:#0b6bcb;--err:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#212120;--fg:#ecebe7;--muted:#a3a29d;--line:#3a3936;--accent:#5aa6f0;--err:#f0857a}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,sans-serif;padding:16px}
main{width:100%;max-width:380px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px}
h1{font-size:20px;margin:0 0 4px}p{margin:0 0 18px;color:var(--muted);font-size:14px}
label{display:block;font-size:13px;font-weight:600;margin:14px 0 6px}
input{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:9px;background:transparent;color:var(--fg);font-size:16px}
input:focus{outline:2px solid var(--accent);outline-offset:1px}
button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:9px;background:var(--accent);color:#fff;font-size:16px;font-weight:600;cursor:pointer}
.err{color:var(--err);font-size:14px;margin:0 0 6px}.fine{margin:16px 0 0;font-size:12px}
</style></head><body><main>${body}</main></body></html>`;
}

function loginForm(state: string, heading: string, error?: string): string {
	return page(heading, `<h1>${escapeHtml(heading)}</h1>
<p>Sign in with your Garmin Connect account.</p>
${error ? `<p class="err" role="alert">${escapeHtml(error)}</p>` : ''}
<form method="post" action="/authorize/login" autocomplete="on">
<input type="hidden" name="state" value="${escapeHtml(state)}">
<label for="email">Garmin email</label><input id="email" name="email" type="email" autocomplete="username" required autofocus>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form>
<p class="fine">Your password goes straight to Garmin and is never stored.</p>`);
}

function mfaForm(state: string, pendingId: string, error?: string): string {
	return page('Verification code', `<h1>Verification code</h1>
<p>Garmin sent a code to your email or authenticator app.</p>
${error ? `<p class="err" role="alert">${escapeHtml(error)}</p>` : ''}
<form method="post" action="/authorize/mfa">
<input type="hidden" name="state" value="${escapeHtml(state)}">
<input type="hidden" name="pending_id" value="${escapeHtml(pendingId)}">
<label for="code">Code</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{4,12}" required autofocus>
<button type="submit">Verify</button>
</form>`);
}

function messagePage(heading: string, message: string): string {
	return page(heading, `<h1>${escapeHtml(heading)}</h1><p>${escapeHtml(message)}</p>`);
}

function sendPage(res: Response, html: string, status = 200): void {
	res
		.status(status)
		.set({
			'Content-Type': 'text/html; charset=utf-8',
			'Cache-Control': 'no-store',
			'X-Frame-Options': 'DENY',
			// form-action also governs the redirect after a successful POST, so it
			// must allow Claude's callback hosts (the only ones /register accepts).
			'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://claude.ai https://claude.com; frame-ancestors 'none'; base-uri 'none'",
			'Referrer-Policy': 'no-referrer',
		})
		.send(html);
}

export function mountOAuthProxy(opts: OAuthProxyOptions): OAuthProxy {
	const { app, baseUrl, loginProvider } = opts;

	const db = new Database(opts.dbPath);
	db.pragma('journal_mode = WAL');
	db.exec(`
		CREATE TABLE IF NOT EXISTS oauth_clients (
			client_id TEXT PRIMARY KEY,
			redirect_uris TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS oauth_pending (
			whoop_state TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			code_challenge TEXT NOT NULL,
			client_state TEXT,
			created_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS oauth_codes (
			code_hash TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			code_challenge TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS oauth_tokens (
			access_hash TEXT PRIMARY KEY,
			refresh_hash TEXT,
			client_id TEXT NOT NULL,
			access_expires_at INTEGER NOT NULL,
			refresh_expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		);
	`);

	function cleanup(): void {
		const now = Date.now();
		db.prepare('DELETE FROM oauth_pending WHERE created_at < ?').run(now - PENDING_TTL_MS);
		db.prepare('DELETE FROM oauth_codes WHERE created_at < ?').run(now - AUTH_CODE_TTL_MS);
		db.prepare('DELETE FROM oauth_tokens WHERE refresh_expires_at < ?').run(now);
		// Registration is unauthenticated, so registered clients accumulate.
		// Drop clients that are old and hold no live tokens (an active Claude
		// client always has a token row, and re-registers if ever pruned).
		db.prepare(`
			DELETE FROM oauth_clients
			WHERE created_at < ?
			AND client_id NOT IN (SELECT client_id FROM oauth_tokens)
		`).run(now - 30 * 24 * 60 * 60 * 1000);
	}
	setInterval(cleanup, 5 * 60 * 1000);

	// Simple in-memory rate limit for the unauthenticated /register endpoint.
	const REGISTER_WINDOW_MS = 60 * 60 * 1000;
	const REGISTER_MAX_PER_WINDOW = 30;
	let registerWindowStart = Date.now();
	let registerCount = 0;

	// ---- Discovery metadata -------------------------------------------------

	const protectedResource = {
		resource: `${baseUrl}/mcp`,
		authorization_servers: [baseUrl],
		scopes_supported: [SCOPE],
		bearer_methods_supported: ['header'],
	};

	const authServerMetadata = {
		issuer: baseUrl,
		authorization_endpoint: `${baseUrl}/authorize`,
		token_endpoint: `${baseUrl}/token`,
		registration_endpoint: `${baseUrl}/register`,
		response_types_supported: ['code'],
		grant_types_supported: ['authorization_code', 'refresh_token'],
		code_challenge_methods_supported: ['S256'],
		token_endpoint_auth_methods_supported: ['none'],
		scopes_supported: [SCOPE],
	};

	// Claude probes the bare path and, as a fallback, the path-suffixed variant.
	app.get('/.well-known/oauth-protected-resource', (_req, res) => res.json(protectedResource));
	app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => res.json(protectedResource));
	app.get('/.well-known/oauth-authorization-server', (_req, res) => res.json(authServerMetadata));
	app.get('/.well-known/oauth-authorization-server/mcp', (_req, res) => res.json(authServerMetadata));

	// ---- Dynamic Client Registration (RFC 7591) -----------------------------

	app.post('/register', (req: Request, res: Response) => {
		const now = Date.now();
		if (now - registerWindowStart > REGISTER_WINDOW_MS) {
			registerWindowStart = now;
			registerCount = 0;
		}
		if (registerCount >= REGISTER_MAX_PER_WINDOW) {
			res.status(429).json({ error: 'too_many_requests', error_description: 'registration rate limit exceeded' });
			return;
		}
		registerCount++;

		const body = (req.body ?? {}) as { redirect_uris?: unknown };
		const redirectUris = Array.isArray(body.redirect_uris)
			? body.redirect_uris.filter((u): u is string => typeof u === 'string')
			: [];

		if (redirectUris.length === 0) {
			res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris required' });
			return;
		}

		// Hardening: only Claude's own callback hosts may be registered as redirect
		// targets, so a crafted client can't divert an authorization code elsewhere.
		const ALLOWED_REDIRECT_HOSTS = new Set(['claude.ai', 'claude.com']);
		const allValid = redirectUris.every(u => {
			try {
				return ALLOWED_REDIRECT_HOSTS.has(new URL(u).hostname);
			} catch {
				return false;
			}
		});
		if (!allValid) {
			console.error('[oauth] /register rejected redirect_uris', JSON.stringify(redirectUris));
			res.status(400).json({ error: 'invalid_redirect_uri', error_description: 'redirect_uri host not allowed' });
			return;
		}

		const clientId = crypto.randomUUID();
		console.log('[oauth] /register ok', JSON.stringify(redirectUris));
		db.prepare('INSERT INTO oauth_clients (client_id, redirect_uris, created_at) VALUES (?, ?, ?)')
			.run(clientId, JSON.stringify(redirectUris), Date.now());

		res.status(201).json({
			client_id: clientId,
			redirect_uris: redirectUris,
			token_endpoint_auth_method: 'none',
			grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'],
		});
	});

	// ---- Authorization endpoint --------------------------------------------

	app.get('/authorize', (req: Request, res: Response) => {
		const { client_id, redirect_uri, response_type, code_challenge, code_challenge_method, state } =
			req.query as Record<string, string | undefined>;

		if (response_type !== 'code') {
			res.status(400).send('unsupported_response_type');
			return;
		}
		if (!code_challenge || code_challenge_method !== 'S256') {
			res.status(400).send('PKCE with S256 is required');
			return;
		}
		if (!client_id || !redirect_uri) {
			res.status(400).send('client_id and redirect_uri are required');
			return;
		}

		const client = db.prepare('SELECT redirect_uris FROM oauth_clients WHERE client_id = ?')
			.get(client_id) as { redirect_uris: string } | undefined;
		if (!client) {
			res.status(400).send('unknown client_id');
			return;
		}
		const allowed = JSON.parse(client.redirect_uris) as string[];
		if (!allowed.includes(redirect_uri)) {
			res.status(400).send('redirect_uri not registered for this client');
			return;
		}

		// Stash Claude's request under a fresh, unguessable state. The sign-in
		// form carries it, and it is the only handle that can complete this flow.
		// (Column is still named whoop_state from the WHOOP era.)
		const loginState = crypto.randomUUID();
		db.prepare(`
			INSERT INTO oauth_pending (whoop_state, client_id, redirect_uri, code_challenge, client_state, created_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`).run(loginState, client_id, redirect_uri, code_challenge, state ?? null, Date.now());

		console.log('[oauth] /authorize ok -> Garmin sign-in page');
		sendPage(res, loginForm(loginState, 'Connect Claude to your health data'));
	});

	// ---- Direct Garmin re-authorization --------------------------------------
	//
	// Reconnects only the Garmin side (fresh Garmin session) without touching
	// Claude's connector tokens — for when the Garmin session dies but the
	// connector itself still works. Unauthenticated by design, and safe that way:
	// the login provider refuses to activate any Garmin account other than the
	// one this server is bound to.
	const REAUTH_CLIENT_ID = '__garmin_reauth__';

	app.get('/reauth', (_req: Request, res: Response) => {
		const loginState = crypto.randomUUID();
		db.prepare(`
			INSERT INTO oauth_pending (whoop_state, client_id, redirect_uri, code_challenge, client_state, created_at)
			VALUES (?, ?, '', '', NULL, ?)
		`).run(loginState, REAUTH_CLIENT_ID, Date.now());
		console.log('[oauth] /reauth -> Garmin sign-in page');
		sendPage(res, loginForm(loginState, 'Reconnect Garmin'));
	});

	// The retired WHOOP callback: say so plainly instead of a bare 404.
	app.get('/callback', (_req: Request, res: Response) => {
		res.status(410).type('text/plain').send('WHOOP sign-in has been retired on this server. Use /reauth to connect Garmin.');
	});

	// ---- Sign-in form handlers ----------------------------------------------

	type PendingRow = { client_id: string; redirect_uri: string; code_challenge: string; client_state: string | null; created_at: number };

	function getPending(state: unknown): PendingRow | null {
		if (typeof state !== 'string' || !state) return null;
		const row = db.prepare('SELECT * FROM oauth_pending WHERE whoop_state = ?').get(state) as PendingRow | undefined;
		if (!row || Date.now() - row.created_at > PENDING_TTL_MS) return null;
		return row;
	}

	let loginWindowStart = Date.now();
	let loginCount = 0;
	function loginAllowed(): boolean {
		const now = Date.now();
		if (now - loginWindowStart > LOGIN_WINDOW_MS) {
			loginWindowStart = now;
			loginCount = 0;
		}
		loginCount++;
		return loginCount <= LOGIN_MAX_PER_WINDOW;
	}

	function userMessage(err: unknown): string {
		if (err instanceof LoginError) return err.message;
		console.error('[oauth] sign-in failed unexpectedly', err instanceof Error ? err.message : err);
		return 'Something went wrong talking to Garmin. Try again shortly.';
	}

	// Finish a successful sign-in: either the reauth page, or Claude's flow.
	function complete(res: Response, state: string, pending: PendingRow): void {
		db.prepare('DELETE FROM oauth_pending WHERE whoop_state = ?').run(state);

		if (pending.client_id === REAUTH_CLIENT_ID) {
			console.log('[oauth] Garmin re-auth complete');
			sendPage(res, messagePage('Garmin connected', 'Garmin is connected and syncing. You can close this tab.'));
			return;
		}

		const authCode = randomToken();
		db.prepare(`
			INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, created_at)
			VALUES (?, ?, ?, ?, ?)
		`).run(sha256hex(authCode), pending.client_id, pending.redirect_uri, pending.code_challenge, Date.now());

		const redirect = new URL(pending.redirect_uri);
		redirect.searchParams.set('code', authCode);
		if (pending.client_state) redirect.searchParams.set('state', pending.client_state);
		console.log('[oauth] sign-in ok -> redirecting to Claude', pending.redirect_uri);
		res.redirect(303, redirect.toString());
	}

	app.post('/authorize/login', async (req: Request, res: Response) => {
		const { state, email, password } = (req.body ?? {}) as Record<string, unknown>;
		const pending = getPending(state);
		if (!pending) {
			sendPage(res, messagePage('Sign-in expired', 'This sign-in link has expired. Start again from Claude (or /reauth).'), 400);
			return;
		}
		const st = state as string;
		if (typeof email !== 'string' || typeof password !== 'string' || !email.trim() || !password) {
			sendPage(res, loginForm(st, 'Sign in', 'Enter your Garmin email and password.'), 400);
			return;
		}
		if (!loginAllowed()) {
			console.error('[oauth] sign-in rate limit hit');
			sendPage(res, loginForm(st, 'Sign in', 'Too many sign-in attempts. Wait 15 minutes and try again.'), 429);
			return;
		}
		try {
			const outcome = await loginProvider.login(email.trim(), password);
			if (outcome.status === 'mfa_required') {
				sendPage(res, mfaForm(st, outcome.pendingId));
				return;
			}
			complete(res, st, pending);
		} catch (err) {
			sendPage(res, loginForm(st, 'Sign in', userMessage(err)), 401);
		}
	});

	app.post('/authorize/mfa', async (req: Request, res: Response) => {
		const { state, pending_id, code } = (req.body ?? {}) as Record<string, unknown>;
		const pending = getPending(state);
		if (!pending || typeof pending_id !== 'string') {
			sendPage(res, messagePage('Sign-in expired', 'This sign-in link has expired. Start again from Claude (or /reauth).'), 400);
			return;
		}
		const st = state as string;
		if (!loginAllowed()) {
			sendPage(res, mfaForm(st, pending_id, 'Too many attempts. Wait 15 minutes and start again.'), 429);
			return;
		}
		try {
			await loginProvider.verifyMfa(pending_id, typeof code === 'string' ? code : '');
			complete(res, st, pending);
		} catch (err) {
			sendPage(res, mfaForm(st, pending_id, userMessage(err)), 401);
		}
	});

	// ---- Token endpoint -----------------------------------------------------

	app.post('/token', (req: Request, res: Response) => {
		const body = (req.body ?? {}) as Record<string, string | undefined>;
		const grantType = body.grant_type;
		console.log('[oauth] /token grant_type=', grantType, 'keys=', Object.keys(body).join(','));

		if (grantType === 'authorization_code') {
			const { code, code_verifier, redirect_uri, client_id } = body;
			if (!code || !code_verifier || !redirect_uri || !client_id) {
				console.error('[oauth] /token invalid_request, missing fields', {
					code: Boolean(code), code_verifier: Boolean(code_verifier),
					redirect_uri: Boolean(redirect_uri), client_id: Boolean(client_id),
				});
				res.status(400).json({ error: 'invalid_request' });
				return;
			}

			const row = db.prepare('SELECT * FROM oauth_codes WHERE code_hash = ?')
				.get(sha256hex(code)) as
				| { client_id: string; redirect_uri: string; code_challenge: string; created_at: number }
				| undefined;

			if (!row || Date.now() - row.created_at > AUTH_CODE_TTL_MS) {
				console.error('[oauth] /token invalid_grant: code not found or expired', { found: Boolean(row) });
				res.status(400).json({ error: 'invalid_grant', error_description: 'code invalid or expired' });
				return;
			}
			if (row.client_id !== client_id || row.redirect_uri !== redirect_uri) {
				console.error('[oauth] /token invalid_grant: client/redirect mismatch', {
					storedClient: row.client_id, sentClient: client_id,
					storedRedirect: row.redirect_uri, sentRedirect: redirect_uri,
				});
				res.status(400).json({ error: 'invalid_grant', error_description: 'client/redirect mismatch' });
				return;
			}
			if (sha256base64url(code_verifier) !== row.code_challenge) {
				console.error('[oauth] /token invalid_grant: PKCE mismatch');
				res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
				return;
			}

			db.prepare('DELETE FROM oauth_codes WHERE code_hash = ?').run(sha256hex(code)); // single use
			console.log('[oauth] /token authorization_code OK, issuing tokens');
			res.json(issueTokens(client_id));
			return;
		}

		if (grantType === 'refresh_token') {
			const { refresh_token, client_id } = body;
			if (!refresh_token || !client_id) {
				res.status(400).json({ error: 'invalid_request' });
				return;
			}

			const row = db.prepare('SELECT * FROM oauth_tokens WHERE refresh_hash = ?')
				.get(sha256hex(refresh_token)) as
				| { client_id: string; refresh_expires_at: number }
				| undefined;

			if (!row || row.client_id !== client_id || Date.now() > row.refresh_expires_at) {
				console.error('[oauth] /token refresh invalid_grant', { found: Boolean(row) });
				res.status(400).json({ error: 'invalid_grant', error_description: 'refresh token invalid or expired' });
				return;
			}

			// No rotation: mint a new access token, return the SAME refresh token,
			// slide the 30-day expiry. Claude refreshes from multiple surfaces and
			// retries on network hiccups; single-use rotation turned any concurrent
			// or retried refresh into invalid_grant -> "reconnect the connector".
			const accessToken = randomToken();
			const now = Date.now();
			db.prepare(`
				UPDATE oauth_tokens
				SET access_hash = ?, access_expires_at = ?, refresh_expires_at = ?
				WHERE refresh_hash = ?
			`).run(sha256hex(accessToken), now + ACCESS_TOKEN_TTL_MS, now + REFRESH_TOKEN_TTL_MS, sha256hex(refresh_token));

			console.log('[oauth] /token refresh OK (non-rotating)');
			res.json({
				access_token: accessToken,
				token_type: 'Bearer',
				expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
				refresh_token,
				scope: SCOPE,
			});
			return;
		}

		console.error('[oauth] /token unsupported_grant_type', grantType);
		res.status(400).json({ error: 'unsupported_grant_type' });
	});

	function issueTokens(clientId: string): {
		access_token: string;
		token_type: string;
		expires_in: number;
		refresh_token: string;
		scope: string;
	} {
		const accessToken = randomToken();
		const refreshToken = randomToken();
		const now = Date.now();
		db.prepare(`
			INSERT INTO oauth_tokens (access_hash, refresh_hash, client_id, access_expires_at, refresh_expires_at, created_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`).run(
			sha256hex(accessToken),
			sha256hex(refreshToken),
			clientId,
			now + ACCESS_TOKEN_TTL_MS,
			now + REFRESH_TOKEN_TTL_MS,
			now
		);
		return {
			access_token: accessToken,
			token_type: 'Bearer',
			expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
			refresh_token: refreshToken,
			scope: SCOPE,
		};
	}

	// ---- Bearer auth middleware for /mcp ------------------------------------

	function requireMcpAuth(req: Request, res: Response, next: NextFunction): void {
		const header = req.headers.authorization ?? '';
		const match = /^Bearer (.+)$/i.exec(header);
		const challenge = `Bearer resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`;

		if (!match) {
			console.log('[oauth] /mcp 401: no bearer token (expected on first connect)');
			res.set('WWW-Authenticate', challenge).status(401).json({ error: 'unauthorized' });
			return;
		}

		const row = db.prepare('SELECT access_expires_at FROM oauth_tokens WHERE access_hash = ?')
			.get(sha256hex(match[1])) as { access_expires_at: number } | undefined;

		if (!row || Date.now() > row.access_expires_at) {
			console.log('[oauth] /mcp 401: token not found or expired', { found: Boolean(row) });
			// 401 prompts Claude to refresh via /token.
			res.set('WWW-Authenticate', challenge).status(401).json({ error: 'invalid_token' });
			return;
		}

		console.log('[oauth] /mcp authorized');
		next();
	}

	return { requireMcpAuth };
}
