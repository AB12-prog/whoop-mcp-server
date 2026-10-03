// src/garmin-analysis.ts — parsing and derived metrics for Garmin activity time
// series and intraday data.

import { LOCAL_TZ } from './garmin.js';

export type Sample = Record<string, number | null>;

/** Resolve Garmin's positional `activityDetailMetrics` into keyed samples. */
export function parseActivitySeries(details: unknown): { keys: string[]; samples: Sample[] } {
	const d = (details ?? {}) as { metricDescriptors?: unknown; activityDetailMetrics?: unknown };
	const index: Array<[number, string]> = [];
	for (const desc of Array.isArray(d.metricDescriptors) ? d.metricDescriptors : []) {
		const key = (desc as { key?: unknown })?.key;
		const i = (desc as { metricsIndex?: unknown })?.metricsIndex;
		if (typeof key === 'string' && typeof i === 'number' && Number.isInteger(i) && i >= 0) index.push([i, key]);
	}
	const samples: Sample[] = [];
	for (const row of Array.isArray(d.activityDetailMetrics) ? d.activityDetailMetrics : []) {
		const metrics = (row as { metrics?: unknown })?.metrics;
		if (!Array.isArray(metrics)) continue;
		const s: Sample = {};
		for (const [i, key] of index) {
			const v = metrics[i];
			s[key] = typeof v === 'number' && Number.isFinite(v) ? v : null;
		}
		samples.push(s);
	}
	return { keys: index.map(([, k]) => k), samples };
}

const n = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);

function mean(xs: number[]): number | null {
	return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null;
}

/** Elapsed seconds for a sample: sumDuration, else derived from directTimestamp. */
function elapsed(samples: Sample[]): number[] {
	const t0 = samples.find(s => n(s.directTimestamp))?.directTimestamp ?? null;
	return samples.map((s, i) => (n(s.sumDuration) ? s.sumDuration : n(s.directTimestamp) && t0 != null ? (s.directTimestamp - t0) / 1000 : i));
}

export interface HalfSplit {
	seconds: number;
	speed: number | null;
	gap: number | null;
	hr: number | null;
	cadence: number | null;
}

export interface SeriesInsights {
	duration_s: number;
	first: HalfSplit;
	second: HalfSplit;
	/** Pa:HR decoupling %, positive = HR rose relative to pace (aerobic drift). Uses GAP when present. */
	decoupling_pct: number | null;
	/** HR change from first to second half at the effort actually run. */
	hr_drift_bpm: number | null;
	/** Rough steadiness: coefficient of variation of moving pace, %. */
	pace_cv_pct: number | null;
	samples: number;
}

/** First vs second half comparison plus aerobic decoupling for steady efforts. */
export function seriesInsights(samples: Sample[]): SeriesInsights | null {
	if (samples.length < 20) return null;
	const t = elapsed(samples);
	const total = t[t.length - 1] - t[0];
	if (!(total >= 600)) return null; // under 10 minutes there's nothing meaningful to say
	const mid = t[0] + total / 2;
	const cadenceKey = samples.some(s => n(s.directDoubleCadence)) ? 'directDoubleCadence' : 'directRunCadence';
	const halves: Array<{ speed: number[]; gap: number[]; hr: number[]; cad: number[]; secs: number }> = [
		{ speed: [], gap: [], hr: [], cad: [], secs: total / 2 },
		{ speed: [], gap: [], hr: [], cad: [], secs: total / 2 },
	];
	const moving: number[] = [];
	samples.forEach((s, i) => {
		const h = halves[t[i] < mid ? 0 : 1];
		const speed = s.directSpeed;
		const isMoving = n(speed) && speed > 0.5;
		if (isMoving) {
			h.speed.push(speed);
			moving.push(speed);
		}
		if (isMoving && n(s.directGradeAdjustedSpeed) && s.directGradeAdjustedSpeed > 0) h.gap.push(s.directGradeAdjustedSpeed);
		if (n(s.directHeartRate) && s.directHeartRate > 30) h.hr.push(s.directHeartRate);
		const cad = s[cadenceKey];
		if (isMoving && n(cad) && cad > 0) h.cad.push(cad);
	});
	const half = (h: (typeof halves)[number]): HalfSplit => ({
		seconds: h.secs,
		speed: mean(h.speed),
		gap: mean(h.gap),
		hr: mean(h.hr),
		cadence: mean(h.cad),
	});
	const first = half(halves[0]);
	const second = half(halves[1]);
	const ef = (h: HalfSplit) => {
		const v = h.gap ?? h.speed;
		return v != null && h.hr ? v / h.hr : null;
	};
	const ef1 = ef(first);
	const ef2 = ef(second);
	const m = mean(moving);
	const sd = m != null && moving.length > 1 ? Math.sqrt(moving.reduce((a, x) => a + (x - m) ** 2, 0) / (moving.length - 1)) : null;
	return {
		duration_s: total,
		first,
		second,
		decoupling_pct: ef1 && ef2 ? ((ef1 - ef2) / ef1) * 100 : null,
		hr_drift_bpm: first.hr != null && second.hr != null ? second.hr - first.hr : null,
		pace_cv_pct: m && sd != null ? (sd / m) * 100 : null,
		samples: samples.length,
	};
}

/** Average samples into fixed time buckets for a compact table. */
export function resampleSeries(samples: Sample[], bucketSeconds: number, keys: string[]): Array<Record<string, number | null>> {
	const t = elapsed(samples);
	const buckets = new Map<number, Record<string, number[]>>();
	samples.forEach((s, i) => {
		const b = Math.floor((t[i] - t[0]) / bucketSeconds);
		let acc = buckets.get(b);
		if (!acc) buckets.set(b, (acc = {}));
		for (const k of keys) {
			const v = s[k];
			if (n(v)) (acc[k] ??= []).push(v);
		}
	});
	return [...buckets.entries()]
		.sort((a, b) => a[0] - b[0])
		.map(([b, acc]) => {
			const row: Record<string, number | null> = { t_s: b * bucketSeconds };
			for (const k of keys) {
				const vals = acc[k] ?? [];
				// Cumulative channels: report the bucket's end value, not an average.
				row[k] = vals.length ? (k.startsWith('sum') ? vals[vals.length - 1] : mean(vals)) : null;
			}
			return row;
		});
}

// ------------------------------------------------------------- formatting ---

export function fmtPace(speedMs: unknown): string {
	if (!n(speedMs) || speedMs <= 0.3) return '—';
	const secs = Math.round(1000 / speedMs);
	return `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}`;
}

export function fmtDuration(seconds: unknown): string {
	if (!n(seconds)) return '—';
	const s = Math.round(seconds);
	const h = Math.floor(s / 3600);
	const m = Math.floor((s % 3600) / 60);
	const sec = s % 60;
	return h ? `${h}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}` : `${m}:${String(sec).padStart(2, '0')}`;
}

const timeFmt = new Intl.DateTimeFormat('en-GB', { timeZone: LOCAL_TZ, hour: '2-digit', minute: '2-digit', hour12: false });
const dateTimeFmt = new Intl.DateTimeFormat('en-CA', {
	timeZone: LOCAL_TZ,
	year: 'numeric',
	month: '2-digit',
	day: '2-digit',
	hour: '2-digit',
	minute: '2-digit',
	hour12: false,
});

export const localTime = (ms: number): string => timeFmt.format(new Date(ms));
export const localDateTime = (ms: number): string => dateTimeFmt.format(new Date(ms)).replace(',', '');

/** How intraday metrics combine within a bucket. */
export const INTRADAY_AGG: Record<string, 'avg' | 'sum' | 'last' | 'min'> = {
	hr: 'avg',
	stress: 'avg',
	body_battery: 'last',
	respiration: 'avg',
	spo2: 'avg',
	spo2_hourly: 'avg',
	steps: 'sum',
	hrv: 'avg',
	sleep_stage: 'last',
};

export function bucketIntraday(points: Array<{ ts: number; value: number }>, bucketMs: number, agg: 'avg' | 'sum' | 'last' | 'min'): Map<number, number> {
	const groups = new Map<number, number[]>();
	for (const p of points) {
		const b = Math.floor(p.ts / bucketMs) * bucketMs;
		let arr = groups.get(b);
		if (!arr) groups.set(b, (arr = []));
		arr.push(p.value);
	}
	const out = new Map<number, number>();
	for (const [b, vals] of groups) {
		const v =
			agg === 'sum' ? vals.reduce((a, x) => a + x, 0) : agg === 'last' ? vals[vals.length - 1] : agg === 'min' ? Math.min(...vals) : vals.reduce((a, x) => a + x, 0) / vals.length;
		out.set(b, v);
	}
	return out;
}

export const SLEEP_STAGE_NAMES: Record<number, string> = { 0: 'deep', 1: 'light', 2: 'REM', 3: 'awake' };
