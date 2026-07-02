// trigger-sync.mjs  —  the cron service runs this, then exits.
// Zero dependencies (Node 18+ has global fetch). Holds no Whoop token, so there
// is no rotation clash — the connector stays the sole token owner.
//
// Env:  CONNECTOR_URL  (e.g. https://whoop-mcp-server-production-85e0.up.railway.app)
//       SYNC_SECRET    (same value set on the connector)

const base = (process.env.CONNECTOR_URL || '').replace(/\/$/, '');
if (!base) {
	console.error('[trigger-sync] CONNECTOR_URL not set');
	process.exit(1);
}

try {
	const r = await fetch(base + '/sync', {
		method: 'POST',
		headers: { 'x-sync-secret': process.env.SYNC_SECRET || '' },
	});
	const body = await r.text();
	console.log(`[trigger-sync] ${r.status} ${body}`);
	process.exit(r.ok ? 0 : 1); // exit so the cron container spins down
} catch (err) {
	console.error('[trigger-sync] failed', err);
	process.exit(1);
}
