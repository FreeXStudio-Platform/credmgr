'use strict';

/**
 * credmgr HTTP client — for consuming a running credmgr daemon from any
 * Node.js project. Zero third-party dependencies (uses built-in `http`).
 *
 *   const { Client } = require('credmgr/client');
 *   const cm = new Client({ token: process.env.CREDMGR_TOKEN });
 *   const apiKey = await cm.get('ACME_API_KEY');
 *
 * When to use this instead of the library API:
 *   - Your project isn't Node.js (not applicable — use HTTP directly)
 *   - Your project runs in a sandboxed process that can't read the vault file
 *   - You want to share a single decrypted-in-memory vault across many workers
 *   - You want centralized audit logging via the daemon
 */

const http = require('http');
const https = require('https');

class CredmgrError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = 'CredmgrError';
    this.status = status;
    this.body = body;
  }
}

class Client {
  /**
   * @param {object} [opts]
   * @param {string} [opts.host='127.0.0.1']
   * @param {number} [opts.port=9876]
   * @param {string} [opts.token]       — bearer token for non-localhost daemons
   * @param {string} [opts.source]      — tag agent accesses (e.g. 'agent:claude-code')
   * @param {boolean} [opts.https=false]
   * @param {number} [opts.timeout=5000]
   */
  constructor(opts = {}) {
    this.host = opts.host || '127.0.0.1';
    this.port = opts.port || 9876;
    this.token = opts.token || process.env.CREDMGR_TOKEN || null;
    this.source = opts.source || 'client';
    this.https = !!opts.https;
    this.timeout = opts.timeout || 5000;
    this.transport = this.https ? https : http;
  }

  _request(method, pathname, body) {
    return new Promise((resolve, reject) => {
      const headers = {
        'Accept': 'application/json',
        'X-Credmgr-Source': this.source,
      };
      if (this.token) headers['Authorization'] = 'Bearer ' + this.token;
      let payload = null;
      if (body !== undefined) {
        payload = JSON.stringify(body);
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = Buffer.byteLength(payload);
      }
      const req = this.transport.request({
        host: this.host,
        port: this.port,
        path: pathname,
        method,
        headers,
        timeout: this.timeout,
      }, (res) => {
        let chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let parsed = null;
          try { parsed = raw ? JSON.parse(raw) : null; } catch { parsed = raw; }
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            const msg = (parsed && parsed.error) || res.statusMessage || 'request failed';
            reject(new CredmgrError(msg, res.statusCode, parsed));
          }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy(new Error('credmgr daemon not responding (timeout ' + this.timeout + 'ms)'));
      });
      if (payload) req.write(payload);
      req.end();
    });
  }

  // ─── Read ────────────────────────────────────────────────────────────

  /**
   * Read a credential's plaintext value.
   * @param {string} name
   * @returns {Promise<string>}
   */
  async get(name) {
    const res = await this._request('GET',
      '/api/credentials/' + encodeURIComponent(name) + '/value?source=' + encodeURIComponent(this.source));
    return res.value;
  }

  /**
   * Get a credential's metadata (no value).
   */
  async getMetadata(name) {
    return this._request('GET', '/api/credentials/' + encodeURIComponent(name));
  }

  /**
   * Fetch a credential by its ref number.
   */
  async getByRef(ref) {
    const res = await this._request('GET', '/api/ref/' + encodeURIComponent(ref));
    return res;
  }

  // ─── Write ───────────────────────────────────────────────────────────

  async set(name, value, metaOverrides = {}) {
    return this._request('POST', '/api/credentials',
      Object.assign({ name, value }, metaOverrides));
  }

  async rotate(name, newValue) {
    return this._request('POST',
      '/api/credentials/' + encodeURIComponent(name) + '/rotate',
      { value: newValue });
  }

  async remove(name) {
    return this._request('DELETE', '/api/credentials/' + encodeURIComponent(name));
  }

  // ─── Discovery ───────────────────────────────────────────────────────

  async list(filters = {}) {
    const qs = new URLSearchParams();
    for (const k of Object.keys(filters)) {
      if (filters[k]) qs.set(k, filters[k]);
    }
    const suffix = qs.toString() ? '?' + qs.toString() : '';
    return this._request('GET', '/api/credentials' + suffix);
  }

  async search(query) {
    return this._request('GET', '/api/search?q=' + encodeURIComponent(query));
  }

  async listProjects() {
    return this._request('GET', '/api/projects');
  }

  // ─── Admin / Convenience ─────────────────────────────────────────────

  async health() {
    return this._request('GET', '/api/health');
  }

  async stats() {
    return this._request('GET', '/api/stats');
  }

  /**
   * Load every credential matching a filter into a plain object, suitable
   * for spawning a child process with its env vars (e.g. { DATABASE_URL, ... }).
   *
   * WARNING: decrypts every matching credential — use narrow filters only.
   */
  async getEnvObject(filters = {}) {
    const items = await this.list(filters);
    const out = {};
    for (const item of items) {
      try {
        out[item.name] = await this.get(item.name);
      } catch {
        // skip unreadable entries
      }
    }
    return out;
  }
}

module.exports = { Client, CredmgrError };
