import type {
	WhoopTokens,
	WhoopUser,
	WhoopBodyMeasurement,
	WhoopCycle,
	WhoopRecovery,
	WhoopSleep,
	WhoopWorkout,
	WhoopPaginatedResponse,
} from './types.js';

const WHOOP_API_BASE = 'https://api.prod.whoop.com/developer';
const WHOOP_AUTH_BASE = 'https://api.prod.whoop.com/oauth/oauth2';

// Refresh when the access token has less than this long left to live.
const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000;

// The stored WHOOP grant is unusable (no tokens, or WHOOP rejected the refresh
// token). Unlike a transient failure, retrying cannot fix this — the user has
// to re-authorize.
export class WhoopAuthError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'WhoopAuthError';
	}
}

interface WhoopClientConfig {
	clientId: string;
	clientSecret: string;
	redirectUri: string;
	onTokenRefresh?: (tokens: WhoopTokens) => void;
	// Returns the most recently persisted tokens. Refreshes always start from
	// these: WHOOP rotates the refresh token on every use and revokes the whole
	// grant when a rotated token is replayed, so a process must never refresh
	// with an in-memory token that another process has already spent.
	loadTokens?: () => WhoopTokens | null;
}

interface PaginationParams {
	start?: string;
	end?: string;
	limit?: number;
	nextToken?: string;
}

export class WhoopClient {
	private tokens: WhoopTokens | null = null;
	private readonly clientId: string;
	private readonly clientSecret: string;
	private readonly redirectUri: string;
	private readonly onTokenRefresh?: (tokens: WhoopTokens) => void;
	private readonly loadTokens?: () => WhoopTokens | null;

	constructor(config: WhoopClientConfig) {
		this.clientId = config.clientId;
		this.clientSecret = config.clientSecret;
		this.redirectUri = config.redirectUri;
		this.onTokenRefresh = config.onTokenRefresh;
		this.loadTokens = config.loadTokens;
	}

	setTokens(tokens: WhoopTokens): void {
		this.tokens = tokens;
	}

	clearTokens(): void {
		this.tokens = null;
	}

	getAuthorizationUrl(scopes: string[]): string {
		const params = new URLSearchParams({
			client_id: this.clientId,
			redirect_uri: this.redirectUri,
			response_type: 'code',
			scope: scopes.join(' '),
			state: crypto.randomUUID(),
		});
		return `${WHOOP_AUTH_BASE}/auth?${params}`;
	}

	async exchangeCodeForTokens(code: string): Promise<WhoopTokens> {
		const response = await fetch(`${WHOOP_AUTH_BASE}/token`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code,
				client_id: this.clientId,
				client_secret: this.clientSecret,
				redirect_uri: this.redirectUri,
			}),
		});

		if (!response.ok) {
			throw new Error(`Token exchange failed: ${await response.text()}`);
		}

		const data = await response.json() as { access_token: string; refresh_token: string; expires_in: number };
		const tokens: WhoopTokens = {
			access_token: data.access_token,
			refresh_token: data.refresh_token,
			expires_at: Date.now() + data.expires_in * 1000,
		};

		this.tokens = tokens;
		return tokens;
	}

	private refreshPromise: Promise<void> | null = null;

	private async refreshTokens(): Promise<void> {
		// Single-flight: WHOOP rotates refresh tokens on every use, so concurrent
		// refreshes (e.g. syncDays' Promise.all) invalidate each other. All
		// concurrent callers share one in-flight refresh.
		this.refreshPromise ??= this.doRefreshTokens().finally(() => {
			this.refreshPromise = null;
		});
		return this.refreshPromise;
	}

	// Swap to the persisted tokens if they carry a different refresh token than
	// the in-memory copy (i.e. another process rotated more recently — during a
	// deploy the old and new containers briefly overlap, each with its own
	// in-memory copy). Returns true if tokens were adopted.
	private adoptStoredTokens(): boolean {
		const stored = this.loadTokens?.() ?? null;
		if (!stored || stored.refresh_token === this.tokens?.refresh_token) {
			return false;
		}
		console.log('[whoop] adopting newer persisted tokens (rotated outside this process)');
		this.tokens = stored;
		return true;
	}

	private hasFreshAccessToken(): boolean {
		return this.tokens != null && this.tokens.expires_at - Date.now() >= TOKEN_REFRESH_MARGIN_MS;
	}

	// Returns null when the request never got a response (DNS, connect, reset).
	private async postRefresh(refreshToken: string): Promise<globalThis.Response | null> {
		try {
			return await fetch(`${WHOOP_AUTH_BASE}/token`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					grant_type: 'refresh_token',
					refresh_token: refreshToken,
					client_id: this.clientId,
					client_secret: this.clientSecret,
					scope: 'offline', // REQUIRED by WHOOP for a new refresh token to be returned
				}),
			});
		} catch (err) {
			console.error('[whoop] token refresh request failed to send:', err instanceof Error ? err.message : err);
			return null;
		}
	}

	private async acceptRefreshResponse(response: globalThis.Response): Promise<void> {
		const data = await response.json() as { access_token: string; refresh_token?: string; expires_in: number };
		this.tokens = {
			access_token: data.access_token,
			// Defensive: if WHOOP ever omits a new refresh token, keep the old one
			// rather than storing undefined (which permanently kills the session).
			refresh_token: data.refresh_token ?? this.tokens!.refresh_token,
			expires_at: Date.now() + data.expires_in * 1000,
		};
		console.log(`[whoop] token refresh ok (rt …${this.tokens.refresh_token.slice(-6)})`);
		this.persistTokens();
	}

	private persistTokens(): void {
		if (!this.onTokenRefresh || !this.tokens) return;
		try {
			this.onTokenRefresh(this.tokens);
		} catch (err) {
			// A rotated refresh token that never reaches the database strands the
			// grant on the next restart. Retry once, then make the failure loud so
			// it's findable in the logs when that happens.
			try {
				this.onTokenRefresh(this.tokens);
			} catch {
				console.error(
					'[whoop] CRITICAL: rotated refresh token could not be persisted; a restart before the next successful save will require re-authorization.',
					err instanceof Error ? err.message : err
				);
			}
		}
	}

	private async doRefreshTokens(): Promise<void> {
		// Always rotate from the most recently persisted token. If another
		// process already rotated and its access token is still fresh, use that
		// instead of spending another rotation.
		if (this.adoptStoredTokens() && this.hasFreshAccessToken()) {
			return;
		}

		if (!this.tokens?.refresh_token) {
			throw new WhoopAuthError('Not authenticated with WHOOP: no refresh token available');
		}

		let response = await this.postRefresh(this.tokens.refresh_token);

		// Each refresh token is single-use, so a failed rotation can strand the
		// whole grant. Retry outages (no response, 5xx, 429) before giving up:
		// if the request never reached WHOOP the token is still unspent and the
		// retry succeeds; if it did reach WHOOP the token is already spent
		// either way, so retrying loses nothing.
		for (let attempt = 1; attempt <= 2 && (response === null || response.status >= 500 || response.status === 429); attempt++) {
			await new Promise(resolve => setTimeout(resolve, attempt * 1000));
			response = await this.postRefresh(this.tokens.refresh_token);
		}

		if (response === null || response.status >= 500 || response.status === 429) {
			const detail = response ? `WHOOP responded ${response.status}` : 'network error reaching WHOOP';
			throw new Error(`Token refresh failed: ${detail}; will retry on the next sync`);
		}

		if (!response.ok) {
			const body = await response.text();
			// A 4xx means WHOOP no longer accepts the token we sent. Before
			// declaring the grant dead, check whether another process persisted a
			// newer rotation while we were trying, and finish with that one.
			if (this.adoptStoredTokens()) {
				if (this.hasFreshAccessToken()) return;
				const retry = await this.postRefresh(this.tokens.refresh_token);
				if (retry?.ok) {
					await this.acceptRefreshResponse(retry);
					return;
				}
			}
			throw new WhoopAuthError(`WHOOP rejected the stored refresh token (${response.status} ${body}); re-authorization is required`);
		}

		await this.acceptRefreshResponse(response);
	}

	private async request<T>(path: string, params?: Record<string, string>): Promise<T> {
		if (!this.tokens) {
			// Tokens may have been persisted after this process loaded (e.g. a
			// re-authorization completed while the server was already running).
			this.tokens = this.loadTokens?.() ?? null;
		}
		if (!this.tokens) {
			throw new WhoopAuthError('Not authenticated with WHOOP');
		}

		if (this.tokens.expires_at - Date.now() < TOKEN_REFRESH_MARGIN_MS) {
			await this.refreshTokens();
		}

		const url = new URL(`${WHOOP_API_BASE}${path}`);
		if (params) {
			for (const [key, value] of Object.entries(params)) {
				url.searchParams.set(key, value);
			}
		}

		const doFetch = () => fetch(url.toString(), {
			headers: { Authorization: `Bearer ${this.tokens!.access_token}` },
		});

		let response = await doFetch();

		// If WHOOP invalidated the access token early, refresh once and retry.
		if (response.status === 401) {
			await this.refreshTokens();
			response = await doFetch();
		}

		if (!response.ok) {
			throw new Error(`API request failed: ${response.status} ${await response.text()}`);
		}

		return response.json() as Promise<T>;
	}

	async getProfile(): Promise<WhoopUser> {
		return this.request<WhoopUser>('/v2/user/profile/basic');
	}

	async getBodyMeasurement(): Promise<WhoopBodyMeasurement> {
		return this.request<WhoopBodyMeasurement>('/v2/user/measurement/body');
	}

	async getCycles(params?: PaginationParams): Promise<WhoopPaginatedResponse<WhoopCycle>> {
		const queryParams: Record<string, string> = {};
		if (params?.start) queryParams.start = params.start;
		if (params?.end) queryParams.end = params.end;
		if (params?.limit) queryParams.limit = params.limit.toString();
		if (params?.nextToken) queryParams.nextToken = params.nextToken;
		return this.request<WhoopPaginatedResponse<WhoopCycle>>('/v2/cycle', queryParams);
	}

	async getRecoveries(params?: PaginationParams): Promise<WhoopPaginatedResponse<WhoopRecovery>> {
		const queryParams: Record<string, string> = {};
		if (params?.start) queryParams.start = params.start;
		if (params?.end) queryParams.end = params.end;
		if (params?.limit) queryParams.limit = params.limit.toString();
		if (params?.nextToken) queryParams.nextToken = params.nextToken;
		return this.request<WhoopPaginatedResponse<WhoopRecovery>>('/v2/recovery', queryParams);
	}

	async getSleeps(params?: PaginationParams): Promise<WhoopPaginatedResponse<WhoopSleep>> {
		const queryParams: Record<string, string> = {};
		if (params?.start) queryParams.start = params.start;
		if (params?.end) queryParams.end = params.end;
		if (params?.limit) queryParams.limit = params.limit.toString();
		if (params?.nextToken) queryParams.nextToken = params.nextToken;
		return this.request<WhoopPaginatedResponse<WhoopSleep>>('/v2/activity/sleep', queryParams);
	}

	async getWorkouts(params?: PaginationParams): Promise<WhoopPaginatedResponse<WhoopWorkout>> {
		const queryParams: Record<string, string> = {};
		if (params?.start) queryParams.start = params.start;
		if (params?.end) queryParams.end = params.end;
		if (params?.limit) queryParams.limit = params.limit.toString();
		if (params?.nextToken) queryParams.nextToken = params.nextToken;
		return this.request<WhoopPaginatedResponse<WhoopWorkout>>('/v2/activity/workout', queryParams);
	}

	async getAllCycles(params?: { start?: string; end?: string }): Promise<WhoopCycle[]> {
		const results: WhoopCycle[] = [];
		let nextToken: string | undefined;

		do {
			const response = await this.getCycles({ ...params, limit: 25, nextToken });
			results.push(...response.records);
			nextToken = response.next_token;
		} while (nextToken);

		return results;
	}

	async getAllRecoveries(params?: { start?: string; end?: string }): Promise<WhoopRecovery[]> {
		const results: WhoopRecovery[] = [];
		let nextToken: string | undefined;

		do {
			const response = await this.getRecoveries({ ...params, limit: 25, nextToken });
			results.push(...response.records);
			nextToken = response.next_token;
		} while (nextToken);

		return results;
	}

	async getAllSleeps(params?: { start?: string; end?: string }): Promise<WhoopSleep[]> {
		const results: WhoopSleep[] = [];
		let nextToken: string | undefined;

		do {
			const response = await this.getSleeps({ ...params, limit: 25, nextToken });
			results.push(...response.records);
			nextToken = response.next_token;
		} while (nextToken);

		return results;
	}

	async getAllWorkouts(params?: { start?: string; end?: string }): Promise<WhoopWorkout[]> {
		const results: WhoopWorkout[] = [];
		let nextToken: string | undefined;

		do {
			const response = await this.getWorkouts({ ...params, limit: 25, nextToken });
			results.push(...response.records);
			nextToken = response.next_token;
		} while (nextToken);

		return results;
	}
}
