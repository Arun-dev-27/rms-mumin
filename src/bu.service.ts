import { Injectable } from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import type { Request, Response } from 'express';
import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { clientSecret, config } from './config';
import { isAllowedPath, normalizeRelativePath } from './handoff-path';

export interface LocalSession {
  claims: Record<string, unknown>;
  me: unknown;
  kid: string | undefined;
  at: string;
  /** Empty when the session came from a trusted handoff (no token exchange). */
  idToken: string;
}

export interface AppEvent {
  at: string;
  text: string;
  ok: boolean;
}

/** One browser's state in this BU app (a real BU keeps one session per user). */
export interface BrowserState {
  id: string;
  session: LocalSession | null;
  lastError: string | null;
  events: AppEvent[];
  /** Bumped on every change; the page polls it to refresh after a back-channel logout. */
  version: number;
  seen: number;
}

export type HandoffResult =
  | { ok: true; claims: Record<string, unknown>; kid: string | undefined; denied: boolean }
  | { ok: false; code: string };

/** A handoff the user asked for before signing in to this (source) app. */
export interface PendingHandoff {
  targetClientId: string;
  path: string;
}

const AAL2 = 'urn:miqaat:aal:2';

@Injectable()
export class BuService {
  private readonly jwks = createRemoteJWKSet(new URL(`${config.issuer}/.well-known/jwks.json`));
  /** Every localhost port shares one cookie jar, so the cookie name carries the app key. */
  private readonly cookieName = `${config.appKey.replace(/-/g, '_')}_browser`;
  private readonly browsers = new Map<string, BrowserState>();
  /** Sign-ins in progress; `then` = a handoff to continue once signed in. */
  private readonly pendingLogin = new Map<string, { browserId: string; verifier: string; nonce: string; acr: string; at: number; then?: PendingHandoff }>();
  private readonly pendingLogout = new Map<string, { browserId: string; at: number }>();
  /** Back-channel logout jti values already processed (replay protection). */
  private readonly seenLogoutJti = new Map<string, number>();
  /** Handoff assertion jti values already used (a real BU uses Redis SET NX EX). */
  private readonly handoffJti = new Map<string, number>();
  /** Core sids this app ended locally (Logout clicked), so the later back-channel message is still shown. */
  private readonly endedLocally = new Map<string, { at: number; browserIds: Set<string> }>();

  /** Simulates an unavailable back-channel endpoint (answers 503) to watch Core retry. */
  backchannelDown = false;

  constructor() {
    setInterval(() => this.prune(), 60_000).unref();
  }

  // ---- browser state -----------------------------------------------------------------------------

  browser(req: Request, res: Response): BrowserState {
    let id = readCookie(req, this.cookieName);
    if (!/^[A-Za-z0-9_-]{24}$/.test(id)) {
      id = randomBytes(18).toString('base64url');
      // Hosted (https): SameSite=None so the cross-site handoff POST from Core still carries it
      // (*.onrender.com subdomains are different sites).
      const secure = config.baseUrl.startsWith('https:');
      res.cookie(this.cookieName, id, { httpOnly: true, sameSite: secure ? 'none' : 'lax', secure, maxAge: 30 * 24 * 3600_000, path: '/' });
    }
    let state = this.browsers.get(id);
    if (!state) {
      state = { id, session: null, lastError: null, events: [], version: 0, seen: 0 };
      this.browsers.set(id, state);
    }
    state.seen = Date.now();
    return state;
  }

  event(b: BrowserState, text: string, ok = true) {
    b.events.unshift({ at: new Date().toISOString(), text, ok });
    b.events.length = Math.min(b.events.length, 8);
    b.version++;
  }

  fail(b: BrowserState, message: string) {
    b.lastError = message;
    b.version++;
  }

  clear(b: BrowserState) {
    b.session = null;
    b.lastError = null;
    b.events = [];
    b.version++;
  }

  hasSecret(): boolean {
    return Boolean(clientSecret());
  }

  private basicAuth(): string {
    const secret = clientSecret();
    if (!secret) throw new Error('no client secret (set CLIENT_SECRET or CLIENT_SECRET_FILE)');
    return `Basic ${Buffer.from(`${config.clientId}:${secret}`).toString('base64')}`;
  }

  // ---- sign in: Authorization Code + PKCE ---------------------------------------------------------

  /** Returns the Core /auth URL the browser is sent to. `then`: a handoff to continue after sign-in. */
  startLogin(b: BrowserState, acr: string | undefined, maxAge: string | undefined, then?: PendingHandoff): string {
    this.basicAuth(); // fail early when the secret is missing
    const verifier = randomBytes(32).toString('base64url');
    const state = randomBytes(16).toString('base64url');
    const nonce = randomBytes(16).toString('base64url');
    const acrValue = acr === 'aal2' ? AAL2 : '';
    this.pendingLogin.set(state, { browserId: b.id, verifier, nonce, acr: acrValue, at: Date.now(), then });
    const q = new URLSearchParams({
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: `${config.baseUrl}/auth/callback`,
      scope: 'openid profile',
      state,
      nonce,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
      ...(acrValue ? { acr_values: acrValue } : {}),
      ...(maxAge && /^\d+$/.test(maxAge) ? { mfa_max_age: maxAge } : {}),
    });
    return `${config.issuer}/auth?${q}`;
  }

  /** Completes the sign-in; returns where to send the browser next (home, or the handoff it was started for). */
  async finishLogin(b: BrowserState, query: Record<string, string | undefined>): Promise<string> {
    const flow = this.pendingLogin.get(query.state ?? '');
    this.pendingLogin.delete(query.state ?? '');
    const failed = (message: string) => {
      this.fail(b, message);
      return '/';
    };
    if (query.error) return failed(`${query.error}: ${query.error_description ?? ''}`);
    if (!flow || flow.browserId !== b.id) return failed('unknown or reused state');

    const tokenRes = await fetch(`${config.issuer}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: this.basicAuth() },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: query.code ?? '',
        redirect_uri: `${config.baseUrl}/auth/callback`,
        code_verifier: flow.verifier,
      }),
    });
    const tokens = (await tokenRes.json()) as { id_token?: string; access_token?: string; error?: string; error_description?: string };
    if (!tokens.id_token) return failed(`/token: ${tokens.error} ${tokens.error_description ?? ''}`);

    const { payload } = await jwtVerify(tokens.id_token, this.jwks, { issuer: config.issuer, audience: config.clientId, algorithms: ['RS256'] });
    if (payload.nonce !== flow.nonce) return failed('nonce mismatch');
    const me = await fetch(`${config.issuer}/me`, { headers: { authorization: `Bearer ${tokens.access_token}` } }).then((r) => r.json());

    b.session = { claims: payload as Record<string, unknown>, me, kid: decodeProtectedHeader(tokens.id_token).kid, at: new Date().toISOString(), idToken: tokens.id_token };
    b.lastError = flow.acr && payload.acr !== flow.acr ? `asked for ${flow.acr}, got ${String(payload.acr)}` : null;
    this.event(b, `Signed in: ID token verified with JWKS (kid ${b.session.kid}), ${String(payload.acr)}`);
    if (!flow.then) return '/';
    // Signed in because a handoff was asked for: continue it now that the source has a local session.
    return `/handoff?${new URLSearchParams({ target: flow.then.targetClientId, path: flow.then.path })}`;
  }

  // ---- logout -------------------------------------------------------------------------------------

  /** BU-initiated logout: end the local session first, then send the browser to Core /logout. */
  startLogout(b: BrowserState): string {
    const state = randomBytes(16).toString('base64url');
    this.pendingLogout.set(state, { browserId: b.id, at: Date.now() });
    const q = new URLSearchParams({ client_id: config.clientId, post_logout_redirect_uri: `${config.baseUrl}/logged-out`, state });
    if (b.session?.idToken) q.set('id_token_hint', b.session.idToken);
    const sid = b.session?.claims.sid;
    if (typeof sid === 'string') {
      const entry = this.endedLocally.get(sid) ?? { at: Date.now(), browserIds: new Set<string>() };
      entry.browserIds.add(b.id);
      this.endedLocally.set(sid, entry);
    }
    this.event(b, b.session ? 'Logout clicked: local session ended, sent to Core /logout (with id_token_hint)' : 'Logout clicked without a local session: Core asks to confirm');
    b.session = null;
    b.lastError = null;
    return `${config.issuer}/logout?${q}`;
  }

  /** Core sends the browser back here after logout. */
  loggedOut(b: BrowserState, state: string | undefined) {
    const ok = this.pendingLogout.get(state ?? '')?.browserId === b.id;
    this.pendingLogout.delete(state ?? '');
    this.event(b, ok ? `Back from Core: whole ${config.realm} realm signed out` : 'Back from Core with an unknown state', ok);
  }

  /** Back-channel logout: server to server, no browser cookie. Returns the HTTP status to answer. */
  async backchannelLogout(logoutToken: string): Promise<number> {
    if (this.backchannelDown) {
      this.broadcast('Back-channel logout received while "endpoint down" -> answered 503 (Core will retry)', false);
      return 503;
    }
    try {
      const { payload } = await jwtVerify(logoutToken, this.jwks, {
        issuer: config.issuer,
        audience: config.clientId,
        algorithms: ['RS256'],
        typ: 'miqaat-logout+jwt',
        clockTolerance: 30,
      });
      if (payload.auth_realm !== config.realm || typeof payload.sid !== 'string' || typeof payload.jti !== 'string') throw new Error('wrong realm / missing sid or jti');
      const replay = this.seenLogoutJti.has(payload.jti);
      this.seenLogoutJti.set(payload.jti, Date.now());
      const note = replay
        ? `Back-channel logout replayed (jti ${payload.jti.slice(0, 8)}) - ignored, answered 200`
        : `Back-channel logout from Core verified (sid ${payload.sid.slice(0, 8)}, ${String(payload.reason)})`;
      const holders = [...this.browsers.values()].filter((b) => b.session?.claims.sid === payload.sid);
      for (const b of holders) {
        b.session = null;
        this.event(b, replay ? note : `${note} -> local session ended`);
      }
      for (const id of this.endedLocally.get(payload.sid)?.browserIds ?? []) {
        const b = this.browsers.get(id);
        if (b && !holders.includes(b)) this.event(b, replay ? note : `${note} -> local session had already ended`);
      }
      return 200;
    } catch (error) {
      this.broadcast(`Back-channel logout REJECTED: ${error instanceof Error ? error.message : String(error)}`, false);
      return 400;
    }
  }

  setBackchannelDown(b: BrowserState, down: boolean) {
    this.backchannelDown = down;
    this.event(b, `Back-channel endpoint set ${down ? 'DOWN (answers 503)' : 'UP'}`, !down);
  }

  private broadcast(text: string, ok: boolean) {
    for (const b of this.browsers.values()) this.event(b, text, ok);
  }

  // ---- trusted handoff ------------------------------------------------------------------------------

  /**
   * SOURCE side: ask Core for a handoff as this app (never sends the ITS ID). Returns the Core URL to send the
   * browser to, or null. Without a local session the source signs the user in first (Core /auth) and continues
   * the same handoff from the callback.
   */
  async startHandoff(b: BrowserState, targetClientId: string | undefined, path: string | undefined): Promise<string | null> {
    const target = config.peers.find((p) => p.clientId === targetClientId);
    const requestedPath = (path || '/dashboard').slice(0, 512);
    if (!target) {
      this.event(b, `Handoff refused: unknown target ${targetClientId ?? ''}`, false);
      return null;
    }
    if (!b.session) {
      this.event(b, `Handoff to ${target.label} ${requestedPath}: no local session - signing in first, the handoff continues after sign-in`);
      return this.startLogin(b, undefined, undefined, { targetClientId: target.clientId, path: requestedPath });
    }
    const r = await fetch(`${config.issuer}/v1/handoff/requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: this.basicAuth() },
      body: JSON.stringify({ target_client_id: target.clientId, requested_path: requestedPath }),
    });
    const body = (await r.json()) as { browser_redirect_url?: string; error?: string; error_description?: string };
    if (r.status !== 201 || !body.browser_redirect_url) {
      this.event(b, `Handoff to ${target.label} ${requestedPath} refused by Core: ${body.error} (${body.error_description ?? ''})`, false);
      return null;
    }
    this.event(b, `Handoff to ${target.label} ${requestedPath}: Core request created, browser sent to Core`);
    return body.browser_redirect_url;
  }

  /** TARGET side: verify the one-time assertion Core posted. Any failure: no local session. */
  async verifyHandoff(assertion: string): Promise<HandoffResult> {
    if (!assertion) return { ok: false, code: 'HANDOFF_MISSING' };
    if (assertion.length > 8192) return { ok: false, code: 'HANDOFF_MALFORMED' };
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(assertion);
    } catch {
      return { ok: false, code: 'HANDOFF_MALFORMED' };
    }
    if (header.typ !== 'miqaat-handoff+jwt') return { ok: false, code: 'HANDOFF_TYP_INVALID' };
    if (header.alg !== 'RS256') return { ok: false, code: 'HANDOFF_ALG_INVALID' };
    if (!header.kid) return { ok: false, code: 'HANDOFF_KID_UNKNOWN' };
    let claims: Record<string, unknown>;
    try {
      ({ payload: claims } = await jwtVerify(assertion, this.jwks, {
        issuer: config.issuer,
        audience: config.clientId,
        algorithms: ['RS256'],
        typ: 'miqaat-handoff+jwt',
        clockTolerance: 30,
        requiredClaims: ['sub', 'sid', 'jti', 'iat', 'exp', 'auth_time', 'acr', 'amr', 'requested_path', 'source_client_id', 'target_client_id', 'auth_realm'],
      }));
    } catch (error) {
      const code = (error as { code?: string }).code ?? '';
      return {
        ok: false,
        code:
          code === 'ERR_JWT_EXPIRED'
            ? 'HANDOFF_EXPIRED'
            : code === 'ERR_JWKS_NO_MATCHING_KEY'
              ? 'HANDOFF_KID_UNKNOWN'
              : code.includes('CLAIM')
                ? 'HANDOFF_CLAIMS_INVALID'
                : 'HANDOFF_SIGNATURE_INVALID',
      };
    }
    if (claims.target_client_id !== config.clientId) return { ok: false, code: 'HANDOFF_TARGET_MISMATCH' };
    if (claims.auth_realm !== config.realm) return { ok: false, code: 'HANDOFF_REALM_MISMATCH' };
    if (!/^[0-9]{1,10}$/.test(String(claims.sub))) return { ok: false, code: 'HANDOFF_MALFORMED' };
    const now = Date.now();
    if (this.handoffJti.has(String(claims.jti))) return { ok: false, code: 'HANDOFF_REPLAYED' };
    this.handoffJti.set(String(claims.jti), now);
    const path = normalizeRelativePath(claims.requested_path);
    if (!path || path !== claims.requested_path || !isAllowedPath(path, config.handoffPaths)) return { ok: false, code: 'HANDOFF_PATH_INVALID' };
    // Target-local authorization (demo policy): nobody has the admin role in these demo apps.
    return { ok: true, claims, kid: header.kid, denied: path.startsWith('/admin/') };
  }

  acceptHandoff(b: BrowserState, claims: Record<string, unknown>, kid: string | undefined) {
    b.session = { claims, me: { note: 'signed in by trusted handoff (no token exchange)', source: claims.source_client_id }, kid, at: new Date().toISOString(), idToken: '' };
    b.lastError = null;
    this.event(b, `Handoff from ${String(claims.source_client_id)} verified (JWKS, one-time jti) -> local session for ITS ${String(claims.sub)} -> ${String(claims.requested_path)}`);
  }

  // ---- housekeeping ---------------------------------------------------------------------------------

  private prune() {
    const now = Date.now();
    for (const [k, v] of this.pendingLogin) if (now - v.at > 600_000) this.pendingLogin.delete(k);
    for (const [k, v] of this.pendingLogout) if (now - v.at > 600_000) this.pendingLogout.delete(k);
    for (const [k, t] of this.seenLogoutJti) if (now - t > 600_000) this.seenLogoutJti.delete(k);
    for (const [k, t] of this.handoffJti) if (now - t > 120_000) this.handoffJti.delete(k);
    for (const [k, v] of this.endedLocally) if (now - v.at > 600_000) this.endedLocally.delete(k);
    for (const [k, b] of this.browsers) if (now - b.seen > 24 * 3600_000) this.browsers.delete(k);
  }
}

function readCookie(req: Request, name: string): string {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}
