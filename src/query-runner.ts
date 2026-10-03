// src/query-runner.ts — runs one read-only SQL query in a separate process.
//
// garmin_query hands model-written SQL to SQLite. better-sqlite3 is
// synchronous and can't be interrupted, so a runaway query in the main process
// would freeze the whole server (MCP, sign-in, cron). Running it here lets the
// parent enforce a hard timeout with SIGKILL and cap memory. The parent has
// already validated the statement; this opens the file read-only regardless.

import Database from 'better-sqlite3';
import { gunzipSync } from 'node:zlib';

interface Job {
	dbPath: string;
	sql: string;
	maxRows: number;
}

process.once('message', (job: Job) => {
	try {
		const db = new Database(job.dbPath, { readonly: true, fileMustExist: true });
		db.pragma('busy_timeout = 2000');
		db.function('gunzip_json', { deterministic: true }, (blob: unknown) => (Buffer.isBuffer(blob) ? gunzipSync(blob).toString('utf8') : null));
		const stmt = db.prepare(job.sql);
		if (!stmt.reader || !stmt.readonly) throw new Error('Only read-only queries that return rows are allowed.');
		stmt.raw(true);
		const columns = stmt.columns().map(c => c.name);
		const rows: unknown[][] = [];
		let truncated = false;
		for (const row of stmt.iterate() as IterableIterator<unknown[]>) {
			if (rows.length >= job.maxRows) {
				truncated = true;
				break;
			}
			rows.push(row.map(v => (Buffer.isBuffer(v) ? `<${v.length} bytes gzip — wrap in gunzip_json()>` : typeof v === 'bigint' ? Number(v) : v)));
		}
		db.close();
		process.send?.({ ok: true, columns, rows, truncated }, undefined, undefined, () => process.exit(0));
	} catch (err) {
		process.send?.({ ok: false, error: err instanceof Error ? err.message : String(err) }, undefined, undefined, () => process.exit(0));
	}
});
