#!/usr/bin/env node
import { countSpfLookups, dohResolver, isDomainName, systemResolver } from "../src/index.js";

const HELP = `Usage: spf-lookup-counter <domain> [options]

Counts the DNS lookups an SPF record needs (limit 10) and the void
lookups (limit 2), and shows which include costs how many.

Options:
  --json             Print the full result as JSON
  --server <ip>      Use this DNS server instead of the system one (repeatable)
  --doh [url]        Use DNS-over-HTTPS (default https://cloudflare-dns.com/dns-query)
  -h, --help         Show this help

Exit codes: 0 no errors, 1 errors found, 2 could not complete (no errors
found so far), 64 bad usage.
`;

const out = (s = "") => process.stdout.write(`${s}\n`);

function parseArgs(argv) {
  const opts = { json: false, servers: [], doh: null, domain: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--server") opts.servers.push(argv[++i]);
    else if (a === "--doh") opts.doh = argv[i + 1] && !argv[i + 1].startsWith("-") && argv[i + 1].startsWith("https://") ? argv[++i] : "https://cloudflare-dns.com/dns-query";
    else if (a.startsWith("-")) return { error: `Unknown option: ${a}` };
    else if (!opts.domain) opts.domain = a;
    else return { error: `Unexpected argument: ${a}` };
  }
  return opts;
}

function printTree(node, depth) {
  for (const c of node.children) {
    const label = `${"  ".repeat(depth)}${c.term}`;
    const notes = [];
    if (c.void) notes.push("void");
    out(`${label.padEnd(48)} ${String(c.total).padStart(3)}${notes.length ? `  (${notes.join(", ")})` : ""}`);
    printTree(c, depth + 1);
  }
}

const opts = parseArgs(process.argv.slice(2));
if (opts.error || opts.help || !opts.domain) {
  if (opts.error) process.stderr.write(`${opts.error}\n\n`);
  process.stdout.write(HELP);
  process.exit(opts.help ? 0 : 64);
}
if (!isDomainName(opts.domain)) {
  process.stderr.write(`Not a domain name: ${opts.domain}\n`);
  process.exit(64);
}

const resolver = opts.doh ? dohResolver({ endpoint: opts.doh }) : systemResolver({ servers: opts.servers });
const r = await countSpfLookups(opts.domain, { resolver });

if (opts.json) {
  out(JSON.stringify(r, null, 2));
} else {
  out(r.domain);
  if (r.record) out(`  ${r.record}`);
  out();
  const atLeast = r.complete ? "" : "at least ";
  const over = r.lookups > r.lookupLimit;
  out(`DNS lookups:  ${atLeast}${r.lookups} of ${r.lookupLimit} allowed${over ? "  OVER THE LIMIT" : ""}`);
  out(`Void lookups: ${atLeast}${r.voidLookups} of ${r.voidLookupLimit} allowed${r.voidLookups > r.voidLookupLimit ? "  OVER THE LIMIT" : ""}`);
  if (r.tree.children.length) {
    out();
    out(`${"Term".padEnd(48)} Lookups`);
    printTree(r.tree, 0);
  }
  if (r.problems.length) {
    out();
    for (const p of r.problems) out(`[${p.severity}] ${p.message}`);
  }
  if (!r.complete) {
    out();
    out("Could not complete: some lookups failed or could not be followed, so the counts above are a lower bound.");
  }
}

const hasError = r.problems.some((p) => p.severity === "error");
process.exit(hasError ? 1 : r.complete ? 0 : 2);
