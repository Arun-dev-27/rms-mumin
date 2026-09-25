import { readFileSync } from 'node:fs';

// .env is optional (the variables may come from the shell instead).
try {
  process.loadEnvFile('.env');
} catch {
  /* no .env file */
}

export interface Peer {
  clientId: string;
  label: string;
  realm: string;
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set (see .env.example)`);
  return value;
}

/** PEER_APPS=ams-admin-dev:AMS Admin:ADMIN,rms-mumin-dev:RMS Mumin:MUMIN */
function parsePeers(value: string): Peer[] {
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [clientId, label, realm] = entry.split(':').map((s) => s.trim());
      return { clientId, label: label || clientId, realm: realm || '' };
    });
}

const port = Number(process.env.PORT ?? 5173);

export const config = {
  appKey: required('APP_KEY'),
  label: required('APP_LABEL'),
  clientId: required('CLIENT_ID'),
  realm: required('APP_REALM'),
  port,
  host: process.env.HOST || '127.0.0.1',
  baseUrl: (process.env.BASE_URL || `http://localhost:${port}`).replace(/\/+$/, ''),
  issuer: (process.env.ISSUER || 'http://localhost:4000').replace(/\/+$/, ''),
  peers: parsePeers(process.env.PEER_APPS ?? ''),
  handoffPaths: (process.env.HANDOFF_PATHS || '/dashboard,/events/*,/events/*/details,/bookings/*,/admin/*')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean),
};

/**
 * The client secret: CLIENT_SECRET, or the file printed by `npm run client:register` in oidc_mfa_auth
 * (read on every use, so a secret rotated in the Test Console is picked up without a restart).
 */
export function clientSecret(): string | null {
  if (process.env.CLIENT_SECRET) return process.env.CLIENT_SECRET;
  const file = process.env.CLIENT_SECRET_FILE;
  if (!file) return null;
  try {
    return readFileSync(file, 'utf8').match(/shown once[^:]*: (\S+)/)?.[1] ?? null;
  } catch {
    return null;
  }
}
