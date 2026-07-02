// src/oauth-proxy.ts
//
// Turns the WHOOP MCP server into a minimal OAuth 2.1 authorization server
// that Claude.ai's web custom connector can authenticate against.
//
// Design: this is an OAuth *proxy*. Claude authenticates to THIS server; the
// /authorize step redirects the user to WHOOP's real login, and only after a
// successful WHOOP login does this server mint a Claude authorization code.
// That means there is no "rubber stamp" hole: to obtain a token you must
// actually log in to the WHOOP account. Completing Claude's OAuth flow also
// authenticates WHOOP as a side effect (the WHOOP tokens get saved in /callback),
// so a single login wires up both sides.
//
// Standards notes:
//  - PKCE S256 is required (Claude always sends it).
//  - Dynamic Client Registration (/register) is supported; Claude registers as a
//    public client (token_endpoint_auth_method = "none"), so no client secret.
//  - Authorization codes are single-use and short-lived.
//  - Server-issued access/refresh tokens are stored only as SHA-256 hashes.
//  - Refresh tokens rotate on use (OAuth 2.1 requirement for public clients).

import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import type { Express, Request, Response, NextFunction } from 'express';

const WHOOP_AUTH_BASE = 'https://api.prod.whoop.com/oauth/oauth2';

// WHOOP scopes requested during the proxied login. read:profile pulls name+email;
// drop it if you want the server to never receive any identifying field.
const WHOOP_SCOPES = [
	'read:profile',
	'read:body_measurement',
	'read:cycles',
	'read:recovery',
	'read:sleep',
	'read:workout',
	'offline',
];

const ACCESS_TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours — fewer refreshes = fewer races with Claude
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const AUTH_CODE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const PENDING_TTL_MS = 10 * 60 * 1000; // 10 minutes

interface OAuthProxyOptions {
	app: Express;
	dbPath: string;
	baseUrl: string; // public https URL of THIS server, no trailing slash
	whoopClientId: string;
	whoopRedirectUri: string; // must equal `${baseUrl}/callback`
	// Exchanges a WHOOP authorization code for tokens and persists them.
	// Provided by index.ts so this module stays decoupled from the WHOOP client.
	exchangeAndSaveWhoopCode: (code: string) => Promise<void>;
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

export function mountOAuthProxy(opts: OAuthProxyOptions): OAuthProxy {
	const { app, baseUrl, whoopClientId, whoopRedirectUri, exchangeAndSaveWhoopCode } = opts;

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
	}
	setInterval(cleanup, 5 * 60 * 1000);

	// ---- Discovery metadata -------------------------------------------------

	const protectedResource = {
		resource: `${baseUrl}/mcp`,
		authorization_servers: [baseUrl],
		scopes_supported: ['whoop:read'],
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
		scopes_supported: ['whoop:read'],
	};

	// Claude probes the bare path and, as a fallback, the path-suffixed variant.
	app.get('/.well-known/oauth-protected-resource', (_req, res) => res.json(protectedResource));
	app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => res.json(protectedResource));
	app.get('/.well-known/oauth-authorization-server', (_req, res) => res.json(authServerMetadata));
	app.get('/.well-known/oauth-authorization-server/mcp', (_req, res) => res.json(authServerMetadata));

	// ---- Dynamic Client Registration (RFC 7591) -----------------------------

	app.post('/register', (req: Request, res: Response) => {
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

		// Stash Claude's request, keyed by a fresh state we hand to WHOOP.
		const whoopState = crypto.randomUUID();
		db.prepare(`
			INSERT INTO oauth_pending (whoop_state, client_id, redirect_uri, code_challenge, client_state, created_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`).run(whoopState, client_id, redirect_uri, code_challenge, state ?? null, Date.now());

		console.log('[oauth] /authorize ok -> redirecting to WHOOP login');
		const params = new URLSearchParams({
			client_id: whoopClientId,
			redirect_uri: whoopRedirectUri,
			response_type: 'code',
			scope: WHOOP_SCOPES.join(' '),
			state: whoopState,
		});
		res.redirect(`${WHOOP_AUTH_BASE}/auth?${params.toString()}`);
	});

	// ---- WHOOP callback (completes both WHOOP auth and Claude's flow) --------

	app.get('/callback', async (req: Request, res: Response) => {
		const code = req.query.code as string | undefined;
		const state = req.query.state as string | undefined;
		const error = req.query.error as string | undefined;
		console.log('[oauth] /callback hit', { hasCode: Boolean(code), hasState: Boolean(state), hasError: Boolean(error) });

		if (error) {
			// Do NOT reflect the raw error value into the response (XSS guard).
			console.error('[oauth] /callback WHOOP returned error:', error);
			res.status(400).type('text/plain').send('WHOOP authorization was denied or failed.');
			return;
		}
		if (!code || !state) {
			res.status(400).type('text/plain').send('Missing authorization code or state.');
			return;
		}

		// Validate FIRST: only act on a flow this server actually started. This blocks
		// unsolicited callbacks from triggering a token exchange or overwriting tokens.
		const pending = db.prepare('SELECT * FROM oauth_pending WHERE whoop_state = ?').get(state) as
			| { client_id: string; redirect_uri: string; code_challenge: string; client_state: string | null }
			| undefined;
		if (!pending) {
			console.error('[oauth] /callback rejected: unknown or expired state');
			res.status(400).type('text/plain').send('Unknown or expired authorization request.');
			return;
		}

		// Now it's safe to exchange the WHOOP code and persist tokens.
		try {
			await exchangeAndSaveWhoopCode(code);
			console.log('[oauth] /callback WHOOP tokens saved');
		} catch (e) {
			console.error('[oauth] /callback WHOOP exchange FAILED', e instanceof Error ? e.message : e);
			res.status(500).type('text/plain').send('WHOOP token exchange failed.');
			return;
		}

		db.prepare('DELETE FROM oauth_pending WHERE whoop_state = ?').run(state);

		const authCode = randomToken();
		db.prepare(`
			INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, created_at)
			VALUES (?, ?, ?, ?, ?)
		`).run(sha256hex(authCode), pending.client_id, pending.redirect_uri, pending.code_challenge, Date.now());

		const redirect = new URL(pending.redirect_uri);
		redirect.searchParams.set('code', authCode);
		if (pending.client_state) redirect.searchParams.set('state', pending.client_state);
		console.log('[oauth] /callback -> redirecting to Claude', pending.redirect_uri);
		res.redirect(redirect.toString());
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
				scope: 'whoop:read',
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
			scope: 'whoop:read',
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
