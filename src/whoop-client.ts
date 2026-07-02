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

interface WhoopClientConfig {
	clientId: string;
	clientSecret: string;
	redirectUri: string;
	onTokenRefresh?: (tokens: WhoopTokens) => void;
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

	constructor(config: WhoopClientConfig) {
		this.clientId = config.clientId;
		this.clientSecret = config.clientSecret;
		this.redirectUri = config.redirectUri;
		this.onTokenRefresh = config.onTokenRefresh;
	}

	setTokens(tokens: WhoopTokens): void {
		this.tokens = tokens;
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

	private async doRefreshTokens(): Promise<void> {
		if (!this.tokens?.refresh_token) {
			throw new Error('No refresh token available');
		}

		const response = await fetch(`${WHOOP_AUTH_BASE}/token`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'refresh_token',
				refresh_token: this.tokens.refresh_token,
				client_id: this.clientId,
				client_secret: this.clientSecret,
				scope: 'offline', // REQUIRED by WHOOP for a new refresh token to be returned
			}),
		});

		if (!response.ok) {
			throw new Error(`Token refresh failed: ${await response.text()}`);
		}

		const data = await response.json() as { access_token: string; refresh_token?: string; expires_in: number };
		this.tokens = {
			access_token: data.access_token,
			// Defensive: if WHOOP ever omits a new refresh token, keep the old one
			// rather than storing undefined (which permanently kills the session).
			refresh_token: data.refresh_token ?? this.tokens.refresh_token,
			expires_at: Date.now() + data.expires_in * 1000,
		};

		this.onTokenRefresh?.(this.tokens);
	}

	private async request<T>(path: string, params?: Record<string, string>): Promise<T> {
		if (!this.tokens) {
			throw new Error('Not authenticated');
		}

		if (this.tokens.expires_at - Date.now() < 5 * 60 * 1000) {
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
