import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;

let cachedKey: Buffer | null = null;

function getEncryptionKey(): Buffer {
	if (cachedKey) return cachedKey;
	const secret = process.env.ENCRYPTION_SECRET || process.env.WHOOP_CLIENT_SECRET;
	if (!secret) {
		throw new Error('No encryption secret available');
	}
	const salt = Buffer.from('whoop-mcp-token-encryption', 'utf8');
	cachedKey = scryptSync(secret, salt, KEY_LENGTH);
	return cachedKey;
}

export function encrypt(text: string): string {
	const key = getEncryptionKey();
	const iv = randomBytes(IV_LENGTH);
	const cipher = createCipheriv(ALGORITHM, key, iv);

	let encrypted = cipher.update(text, 'utf8', 'hex');
	encrypted += cipher.final('hex');

	const authTag = cipher.getAuthTag();

	return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

export function decrypt(encryptedData: string): string {
	const key = getEncryptionKey();
	const [ivHex, authTagHex, encrypted] = encryptedData.split(':');

	if (!ivHex || !authTagHex || !encrypted) {
		throw new Error('Invalid encrypted data format');
	}

	const iv = Buffer.from(ivHex, 'hex');
	const authTag = Buffer.from(authTagHex, 'hex');
	const decipher = createDecipheriv(ALGORITHM, key, iv);
	decipher.setAuthTag(authTag);

	let decrypted = decipher.update(encrypted, 'hex', 'utf8');
	decrypted += decipher.final('utf8');

	return decrypted;
}

export function isEncrypted(data: string): boolean {
	const parts = data.split(':');
	return parts.length === 3 && parts[0].length === IV_LENGTH * 2;
}
