/**
 * spf-lookup-counter: count the DNS lookups an SPF record costs, the way a
 * receiving mail server would, and show which include uses how many.
 *
 * RFC 7208 §4.6.4: evaluating SPF may cause at most 10 DNS-querying terms
 * (include, a, mx, ptr, exists and the redirect modifier) and at most 2 "void"
 * lookups (a query that returns NXDOMAIN or no answers). Going over either
 * limit makes receivers return "permerror", so SPF stops working.
 *
 * Zero dependencies. The DNS resolver is pluggable (see ./resolvers.js).
 */

import { systemResolver } from "./resolvers.js";

export const LOOKUP_LIMIT = 10;
export const VOID_LOOKUP_LIMIT = 2;
export const MX_RECORD_LIMIT = 10;
export const DEFAULT_MAX_QUERIES = 60;
const MAX_DEPTH = 12;

const MECHANISMS = new Set(["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"]);
const LOOKUP_MECHANISMS = new Set(["include", "a", "mx", "ptr", "exists"]);
const KNOWN_MODIFIERS = new Set(["redirect", "exp"]);

/** TXT strings that are SPF records (start with "v=spf1"). */
export function spfRecords(txt) {
  return txt.filter((t) => /^v=spf1(\s|$)/i.test(String(t).trim()));
}

/**
 * Split an SPF record into mechanisms and modifiers.
 * @param {string} record
 */
export function parseSpf(record) {
  const mechanisms = [];
  const modifiers = [];
  const invalid = [];
  for (const raw of String(record).trim().split(/\s+/).slice(1)) {
    const mod = /^([a-z][a-z0-9._-]*)=(.*)$/i.exec(raw);
    if (mod) {
      const name = mod[1].toLowerCase();
      // Unknown modifiers are ignored (RFC 7208 §6), so they are not errors.
      if (KNOWN_MODIFIERS.has(name)) modifiers.push({ name, value: mod[2], raw });
      continue;
    }
    const m = /^([+\-~?]?)([a-z][a-z0-9]*)(?::([^/]*))?(\/.*)?$/i.exec(raw);
    const name = m?.[2]?.toLowerCase();
    if (!m || !name || !MECHANISMS.has(name)) {
      invalid.push(raw);
      continue;
    }
    const value = m[3];
    const needsValue = name === "include" || name === "exists" || name === "ip4" || name === "ip6";
    if ((needsValue && !value) || (name === "all" && (value !== undefined || m[4]))) {
      invalid.push(raw);
      continue;
    }
    mechanisms.push({ qualifier: m[1] || "+", name, value, raw });
  }
  return { mechanisms, modifiers, invalid };
}

function normalize(domain) {
  return String(domain).trim().toLowerCase().replace(/\.$/, "");
}

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i;

/** True when `domain` looks like a DNS name we can query. */
export function isDomainName(domain) {
  return DOMAIN_RE.test(normalize(domain));
}

function isVoid(ans) {
  return ans.status === "nxdomain" || (ans.status === "ok" && ans.records.length === 0);
}

function problem(ctx, severity, code, where, message) {
  const key = `${code}|${where}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.problems.push({ severity, code, where, message });
}

async function query(ctx, name, type) {
  const key = `${name}|${type}`;
  if (ctx.cache.has(key)) return ctx.cache.get(key);
  if (ctx.queries >= ctx.maxQueries) {
    ctx.complete = false;
    problem(ctx, "incomplete", "query_cap_reached", name, `Stopped after ${ctx.maxQueries} DNS queries, so the counts are a lower bound.`);
    return { status: "skipped", records: [] };
  }
  ctx.queries++;
  let ans;
  try {
    ans = await ctx.resolver.query(name, type);
  } catch (err) {
    ans = { status: "error", records: [], detail: err instanceof Error ? err.message : String(err) };
  }
  if (!ans || !Array.isArray(ans.records)) ans = { status: "error", records: [], detail: "resolver returned no answer" };
  ctx.cache.set(key, ans);
  return ans;
}

function failed(ctx, ans, name, type) {
  if (ans.status !== "error" && ans.status !== "skipped") return false;
  ctx.complete = false;
  if (ans.status === "error") problem(ctx, "incomplete", "lookup_failed", name, `${type} lookup for ${name} failed (${ans.detail ?? "error"}), so it could not be counted.`);
  return true;
}

function countVoid(ctx, node, ans) {
  if (!isVoid(ans)) return;
  node.void = true;
  ctx.voids++;
}

/** Follow an include or redirect target and walk its record. */
async function follow(ctx, node, target, path, kind) {
  if (target.includes("%")) {
    ctx.complete = false;
    problem(ctx, "incomplete", "macro_not_expanded", node.term, `${node.term} uses an SPF macro, which depends on the sender, so lookups behind it are not counted.`);
    return;
  }
  if (path.includes(target)) {
    problem(ctx, "error", "loop", node.term, `${node.term} points back to ${target}, which is already being evaluated (a loop). Receivers return permerror.`);
    return;
  }
  if (path.length >= MAX_DEPTH) {
    ctx.complete = false;
    problem(ctx, "incomplete", "too_deep", node.term, `Nesting deeper than ${MAX_DEPTH} levels was not followed.`);
    return;
  }
  const ans = await query(ctx, target, "TXT");
  if (failed(ctx, ans, target, "TXT")) return;
  countVoid(ctx, node, ans);
  const recs = spfRecords(ans.records);
  if (recs.length !== 1) {
    const what = recs.length ? "more than one SPF record" : ans.status === "nxdomain" ? "does not exist" : "has no SPF record";
    problem(ctx, "error", recs.length ? `${kind}_multiple_records` : `${kind}_no_record`, node.term, `${target} ${what}. Receivers return permerror for ${node.term}.`);
    return;
  }
  node.domain = target;
  node.record = recs[0];
  await walk(ctx, node, [...path, target]);
}

async function resolveMechanism(ctx, m, node, child, path) {
  const domainPart = m.value !== undefined && m.value !== "" ? normalize(m.value) : node.domain;
  if (m.name === "include") return follow(ctx, child, normalize(m.value), path, "include");
  if (m.name === "ptr") {
    problem(ctx, "warning", "ptr_used", child.term, `${child.term}: the ptr mechanism is slow and unreliable, and RFC 7208 §5.5 says not to use it. It needs the sender's IP, so its own lookups are not followed here.`);
    return;
  }
  if (domainPart.includes("%")) {
    ctx.complete = false;
    problem(ctx, "incomplete", "macro_not_expanded", child.term, `${child.term} uses an SPF macro, which depends on the sender, so it was counted but not queried.`);
    return;
  }
  if (m.name === "mx") {
    const ans = await query(ctx, domainPart, "MX");
    if (failed(ctx, ans, domainPart, "MX")) return;
    countVoid(ctx, child, ans);
    child.answers = ans.records.length;
    if (ans.records.length > MX_RECORD_LIMIT) {
      problem(ctx, "error", "mx_too_many", child.term, `${domainPart} has ${ans.records.length} MX records; SPF allows at most ${MX_RECORD_LIMIT} for the mx mechanism (RFC 7208 §4.6.4). Receivers return permerror.`);
    }
    return;
  }
  // a and exists: void only when the name has no address at all.
  const a = await query(ctx, domainPart, "A");
  if (failed(ctx, a, domainPart, "A")) return;
  if (m.name === "a" && isVoid(a)) {
    const aaaa = await query(ctx, domainPart, "AAAA");
    if (failed(ctx, aaaa, domainPart, "AAAA")) return;
    countVoid(ctx, child, aaaa);
    child.answers = aaaa.records.length;
    return;
  }
  countVoid(ctx, child, a);
  child.answers = a.records.length;
}

/** Walk one SPF record, adding a child node per DNS-querying term. */
async function walk(ctx, node, path) {
  const { mechanisms, modifiers, invalid } = parseSpf(node.record);
  const where = node.domain;
  if (invalid.length) problem(ctx, "error", "syntax", where, `${where}: terms receivers do not recognise: ${invalid.join(" ")}. Receivers return permerror.`);

  const allIdx = mechanisms.findIndex((m) => m.name === "all");
  // Evaluation stops at "all": anything after it is never reached.
  const evaluated = allIdx === -1 ? mechanisms : mechanisms.slice(0, allIdx + 1);
  if (allIdx !== -1 && allIdx < mechanisms.length - 1) {
    problem(ctx, "warning", "terms_after_all", where, `${where}: ${mechanisms.slice(allIdx + 1).map((m) => m.raw).join(" ")} comes after "all" and is never evaluated.`);
  }

  for (const m of evaluated) {
    if (m.name === "all" && m.qualifier === "+") {
      problem(ctx, "error", "pass_all", where, `${where}: "${m.raw}" lets any server in the world send mail as this domain.`);
    }
    if (!LOOKUP_MECHANISMS.has(m.name)) continue;
    const child = { term: m.raw, lookups: 1, children: [] };
    ctx.lookups++;
    node.children.push(child);
    await resolveMechanism(ctx, m, node, child, path);
  }

  const redirects = modifiers.filter((x) => x.name === "redirect");
  if (redirects.length > 1) problem(ctx, "error", "syntax", where, `${where}: more than one redirect modifier. Receivers return permerror.`);
  const redirect = redirects[0];
  if (redirect) {
    if (allIdx !== -1) {
      problem(ctx, "warning", "redirect_ignored", where, `${where}: ${redirect.raw} is ignored because the record has an "all" mechanism (RFC 7208 §6.1).`);
    } else {
      const child = { term: redirect.raw, lookups: 1, children: [] };
      ctx.lookups++;
      node.children.push(child);
      await follow(ctx, child, normalize(redirect.value), path, "redirect");
    }
  }
  if (path.length === 1) {
    const all = allIdx === -1 ? undefined : mechanisms[allIdx];
    if (!redirect && (!all || all.qualifier === "?")) {
      problem(ctx, "warning", "weak_all", where, `${where}: the record ends without "-all" or "~all", so mail from unlisted servers gets a neutral result.`);
    }
  }
}

function total(node) {
  node.total = (node.lookups ?? 0) + node.children.reduce((s, c) => s + total(c), 0);
  return node.total;
}

/**
 * Count the DNS lookups and void lookups an SPF record needs.
 *
 * @param {string} domain
 * @param {{ resolver?: { query(name: string, type: "TXT"|"A"|"AAAA"|"MX"): Promise<{status: string, records: string[], detail?: string}> }, maxQueries?: number }} [options]
 */
export async function countSpfLookups(domain, options = {}) {
  const name = normalize(domain);
  if (!isDomainName(name)) throw new TypeError(`Not a domain name: ${String(domain)}`);
  const ctx = {
    resolver: options.resolver ?? systemResolver(),
    maxQueries: options.maxQueries ?? DEFAULT_MAX_QUERIES,
    lookups: 0,
    voids: 0,
    queries: 0,
    complete: true,
    problems: [],
    seen: new Set(),
    cache: new Map(),
  };
  const tree = { term: name, domain: name, record: null, lookups: 0, children: [] };
  const ans = await query(ctx, name, "TXT");
  if (!failed(ctx, ans, name, "TXT")) {
    const recs = spfRecords(ans.records);
    if (recs.length === 0) {
      problem(ctx, "error", "no_record", name, ans.status === "nxdomain" ? `${name} does not exist.` : `${name} has no SPF record (no TXT record starting with v=spf1).`);
    } else if (recs.length > 1) {
      problem(ctx, "error", "multiple_records", name, `${name} has ${recs.length} SPF records. A domain must have exactly one; receivers return permerror.`);
    } else {
      tree.record = recs[0];
      await walk(ctx, tree, [name]);
    }
  }
  total(tree);
  if (ctx.lookups > LOOKUP_LIMIT) {
    problem(ctx, "error", "too_many_lookups", name, `${ctx.lookups} DNS lookups; the limit is ${LOOKUP_LIMIT}. Receivers return permerror, so SPF fails for all mail.`);
  }
  if (ctx.voids > VOID_LOOKUP_LIMIT) {
    problem(ctx, "error", "too_many_void_lookups", name, `${ctx.voids} void lookups (names that do not exist or have no records); the limit is ${VOID_LOOKUP_LIMIT}. Receivers may return permerror.`);
  }
  const hasError = ctx.problems.some((p) => p.severity === "error");
  return {
    domain: name,
    record: tree.record,
    lookups: ctx.lookups,
    lookupLimit: LOOKUP_LIMIT,
    voidLookups: ctx.voids,
    voidLookupLimit: VOID_LOOKUP_LIMIT,
    /** false when some lookups could not be made; counts are then a lower bound. */
    complete: ctx.complete,
    /** true only when the count is complete and there are no errors. */
    ok: ctx.complete && !hasError,
    dnsQueries: ctx.queries,
    tree,
    problems: ctx.problems,
  };
}

export { systemResolver, dohResolver, parseTxtData } from "./resolvers.js";
