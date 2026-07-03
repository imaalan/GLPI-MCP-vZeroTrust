/**
 * Hardened GLPI REST client — the only outbound network surface.
 *
 * Every request: fixed origin (host allowlist), TLS enforced upstream in
 * config, request timeout, no redirect following (anti-SSRF), sanitized errors.
 */

import type { Config } from './index.js';

export class GlpiApiError extends Error {
  override readonly name = 'GlpiApiError';
  constructor(readonly status: number, message: string) {
    super(message);
  }
}
export class SecurityError extends Error {
  override readonly name = 'SecurityError';
}

export class GlpiClient {
  private sessionToken: string | null = null;

  constructor(private readonly cfg: Config) {}

  private headers(includeSession: boolean): Record<string, string> {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.cfg.auth.appToken) h['App-Token'] = this.cfg.auth.appToken;
    if (includeSession && this.sessionToken) h['Session-Token'] = this.sessionToken;
    return h;
  }

  private async fetch(path: string, init: RequestInit): Promise<unknown> {
    const url = `${this.cfg.apiBase}/apirest.php${path}`;
    if (new URL(url).origin !== this.cfg.origin) {
      throw new SecurityError('Refusing request outside the allowed GLPI origin.');
    }
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.cfg.timeoutMs);
    try {
      const res = await fetch(url, { ...init, signal: ctl.signal, redirect: 'error' });
      const body = await res.text();
      if (!res.ok) {
        // Sanitize: expose status + first line only, never the raw GLPI body dump.
        throw new GlpiApiError(res.status, `GLPI ${res.status} on ${path}: ${body.slice(0, 200)}`);
      }
      return body ? JSON.parse(body) : null;
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new GlpiApiError(408, `GLPI request timed out after ${this.cfg.timeoutMs}ms on ${path}`);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  async initSession(): Promise<void> {
    const h = this.headers(false);
    if (this.cfg.auth.kind === 'user_token') {
      h['Authorization'] = `user_token ${this.cfg.auth.userToken}`;
    } else {
      const creds = Buffer.from(`${this.cfg.auth.username}:${this.cfg.auth.password}`).toString('base64');
      h['Authorization'] = `Basic ${creds}`;
    }
    const data = (await this.fetch('/initSession', { method: 'GET', headers: h })) as {
      session_token?: string;
    };
    if (!data?.session_token) throw new GlpiApiError(500, 'initSession returned no session_token');
    this.sessionToken = data.session_token;
  }

  async killSession(): Promise<void> {
    if (!this.sessionToken) return;
    try {
      await this.fetch('/killSession', { method: 'GET', headers: this.headers(true) });
    } catch {
      process.stderr.write('{"level":"warn","msg":"killSession failed"}\n');
    } finally {
      this.sessionToken = null;
    }
  }

  private async ensureSession(): Promise<void> {
    if (!this.sessionToken) await this.initSession();
  }

  // ---- Generic verbs (all GLPI itemtypes go through these) -----------------

  async list(itemtype: string, query: Record<string, string | number | boolean> = {}): Promise<unknown> {
    await this.ensureSession();
    const qs = toQuery(query);
    return this.fetch(`/${enc(itemtype)}${qs}`, { method: 'GET', headers: this.headers(true) });
  }

  async get(itemtype: string, id: number, query: Record<string, string | number | boolean> = {}): Promise<unknown> {
    await this.ensureSession();
    return this.fetch(`/${enc(itemtype)}/${id}${toQuery(query)}`, { method: 'GET', headers: this.headers(true) });
  }

  async create(itemtype: string, input: Record<string, unknown>): Promise<unknown> {
    await this.ensureSession();
    return this.fetch(`/${enc(itemtype)}`, {
      method: 'POST',
      headers: this.headers(true),
      body: JSON.stringify({ input }),
    });
  }

  async update(itemtype: string, id: number, input: Record<string, unknown>): Promise<unknown> {
    await this.ensureSession();
    return this.fetch(`/${enc(itemtype)}/${id}`, {
      method: 'PUT',
      headers: this.headers(true),
      body: JSON.stringify({ input }),
    });
  }

  // No delete verb: this client cannot issue HTTP DELETE to GLPI by design.

  /** Sub-item collections, e.g. Ticket/5/ITILFollowup */
  async subList(itemtype: string, id: number, sub: string): Promise<unknown> {
    await this.ensureSession();
    return this.fetch(`/${enc(itemtype)}/${id}/${enc(sub)}`, { method: 'GET', headers: this.headers(true) });
  }

  async search(itemtype: string, criteria: SearchCriterion[]): Promise<unknown> {
    await this.ensureSession();
    const params = new URLSearchParams();
    criteria.forEach((c, i) => {
      params.append(`criteria[${i}][field]`, String(c.field));
      params.append(`criteria[${i}][searchtype]`, c.searchtype);
      params.append(`criteria[${i}][value]`, c.value);
      if (c.link && i > 0) params.append(`criteria[${i}][link]`, c.link);
    });
    return this.fetch(`/search/${enc(itemtype)}?${params.toString()}`, {
      method: 'GET',
      headers: this.headers(true),
    });
  }

  /** Session-scoped endpoints: getMyProfiles, getActiveProfile, getMyEntities, getFullSession */
  async sessionInfo(endpoint: string): Promise<unknown> {
    await this.ensureSession();
    return this.fetch(`/${enc(endpoint)}`, { method: 'GET', headers: this.headers(true) });
  }
}

export interface SearchCriterion {
  field: number;
  searchtype: 'contains' | 'equals' | 'notequals' | 'lessthan' | 'morethan' | 'under' | 'notunder';
  value: string;
  link?: 'AND' | 'OR';
}

const enc = (s: string) => encodeURIComponent(s);

function toQuery(query: Record<string, string | number | boolean>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) p.append(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : '';
}
