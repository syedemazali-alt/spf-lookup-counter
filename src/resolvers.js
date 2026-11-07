/* global AbortSignal */
/**
 * DNS resolvers for spf-lookup-counter. A resolver is any object with
 *   query(name, type) -> Promise<{ status: "ok" | "nxdomain" | "error", records: string[], detail?: string }>
 * where type is "TXT", "A", "AAAA" or "MX". "ok" with no records means the
 * name exists but has no records of that type.
 */

import { Resolver } from "node:dns/promises";

function ok(records) {
  return { status: "ok", records };
}

/**
 * Uses the operating system's configured DNS servers (or `servers`) through
 * node:dns. Nothing is sent anywhere except your DNS resolver.
 * @param {{ servers?: string[], timeoutMs?: number }} [options]
 */
export function systemResolver(options = {}) {
  const r = new Resolver({ timeout: options.timeoutMs ?? 5000, tries: 2 });
  if (options.servers?.length) r.setServers(options.servers);
  return {
    async query(name, type) {
      try {
        switch (type) {
          case "TXT":
            // A TXT record can be split into several strings; SPF joins them (RFC 7208 §3.3).
            return ok((await r.resolveTxt(name)).map((chunks) => chunks.join("")));
          case "A":
            return ok(await r.resolve4(name));
          case "AAAA":
            return ok(await r.resolve6(name));
          case "MX":
            return ok((await r.resolveMx(name)).map((m) => m.exchange));
          default:
            return { status: "error", records: [], detail: `unsupported type ${type}` };
        }
      } catch (err) {
        const code = err && typeof err === "object" && "code" in err ? err.code : undefined;
        if (code === "ENOTFOUND") return { status: "nxdomain", records: [] };
        if (code === "ENODATA") return ok([]);
        return { status: "error", records: [], detail: code ? String(code) : "lookup error" };
      }
    },
  };
}

const RR = { TXT: 16, A: 1, AAAA: 28, MX: 15 };

/**
 * TXT data in DNS JSON arrives as quoted strings, e.g. `"v=spf1 include:a" " -all"`.
 * One TXT record is the concatenation of its strings.
 */
export function parseTxtData(data) {
  const s = String(data).trim();
  if (!s.startsWith('"')) return s;
  const parts = [];
  let i = 0;
  while (i < s.length) {
    if (s[i] !== '"') {
      i++;
      continue;
    }
    i++;
    let cur = "";
    while (i < s.length && s[i] !== '"') {
      if (s[i] === "\\" && i + 1 < s.length) {
        cur += s[i + 1];
        i += 2;
      } else {
        cur += s[i];
        i++;
      }
    }
    parts.push(cur);
    i++;
  }
  return parts.join("");
}

/**
 * DNS-over-HTTPS (JSON API). Useful where system DNS is filtered. The names
 * you look up are sent to the DoH provider (Cloudflare by default).
 * @param {{ endpoint?: string, timeoutMs?: number, fetch?: typeof fetch }} [options]
 */
export function dohResolver(options = {}) {
  const endpoint = options.endpoint ?? "https://cloudflare-dns.com/dns-query";
  const timeoutMs = options.timeoutMs ?? 5000;
  const doFetch = options.fetch ?? fetch;
  return {
    async query(name, type) {
      const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${type}`;
      try {
        const res = await doFetch(url, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(timeoutMs) });
        if (!res.ok) return { status: "error", records: [], detail: `HTTP ${res.status}` };
        const body = await res.json();
        if (body.Status === 3) return { status: "nxdomain", records: [] };
        if (body.Status !== 0) return { status: "error", records: [], detail: `DNS status ${body.Status}` };
        const want = RR[type];
        const records = (body.Answer ?? [])
          .filter((a) => a.type === want && typeof a.data === "string")
          .map((a) => (type === "TXT" ? parseTxtData(a.data) : type === "MX" ? a.data.trim().split(/\s+/).pop().replace(/\.$/, "") : a.data.trim()));
        return ok(records);
      } catch (err) {
        return { status: "error", records: [], detail: err instanceof Error && err.name === "TimeoutError" ? "timed out" : "network error" };
      }
    },
  };
}
