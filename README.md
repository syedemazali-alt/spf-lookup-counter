# spf-lookup-counter

Count the DNS lookups your SPF record needs, and see **which include costs how many**.

SPF allows at most **10 DNS lookups** and **2 void lookups** per check ([RFC 7208 §4.6.4](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4)). Go over either limit and receiving mail servers return `permerror`: SPF stops working for all your mail, and DMARC can no longer pass on SPF. It usually happens quietly, when a provider you `include:` adds another nested include.

Most checkers tell you "more than 10". This tool gives the exact number and the full tree, so you can see which include to remove or replace.

```text
$ npx spf-lookup-counter primedevforce.com
primedevforce.com
  v=spf1 include:secureserver.net -all

DNS lookups:  3 of 10 allowed
Void lookups: 0 of 2 allowed

Term                                             Lookups
include:secureserver.net                           3
  include:spf-0.secureserver.net                   2
    include:spf.protection.outlook.com             1
```

- No dependencies. Node.js 18.17 or later.
- Uses your own DNS resolver by default. Nothing is sent to us.
- Counts are exact, not "more than 10".
- When a lookup fails, the result says **could not complete** and gives a lower bound. A failed lookup is never reported as a pass.

## Install and run

```bash
npx spf-lookup-counter example.com
```

Or install it:

```bash
npm install --save-dev spf-lookup-counter
```

### Options

| Option | What it does |
| --- | --- |
| `--json` | Print the full result (counts, tree, problems) as JSON |
| `--server <ip>` | Use this DNS server instead of the system one. Repeat for more than one |
| `--doh [url]` | Use DNS-over-HTTPS. The default is `https://cloudflare-dns.com/dns-query`. The names you look up are then sent to that provider |
| `-h`, `--help` | Show help |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No errors found and every lookup completed |
| `1` | Errors found (for example over 10 lookups, a loop, `+all`, or an include with no SPF record) |
| `2` | Could not complete: no errors found so far, but some lookups failed or could not be followed |
| `64` | Bad usage (for example, not a domain name) |

This makes it easy to run in CI. For example, fail a DNS change that would break SPF:

```bash
npx spf-lookup-counter example.com || exit 1
```

## Use it as a library

```js
import { countSpfLookups } from "spf-lookup-counter";

const r = await countSpfLookups("example.com");
console.log(r.lookups, "of", r.lookupLimit);   // e.g. 12 of 10
for (const p of r.problems) console.log(p.severity, p.code, p.message);
```

The result:

| Field | Meaning |
| --- | --- |
| `lookups` | DNS-querying terms counted (limit `lookupLimit`, 10) |
| `voidLookups` | Lookups that returned NXDOMAIN or no records (limit `voidLookupLimit`, 2) |
| `complete` | `false` when some lookups failed or could not be followed. The counts are then a lower bound |
| `ok` | `true` only when `complete` is true and there are no errors |
| `tree` | Each term with its own cost (`lookups`) and the cost of everything it pulls in (`total`) |
| `problems` | `{ severity: "error" \| "warning" \| "incomplete", code, where, message }` |

You can pass your own resolver, for example to use a cache or a test zone:

```js
await countSpfLookups("example.com", {
  resolver: { async query(name, type) { return { status: "ok", records: [] }; } },
  maxQueries: 60, // safety cap on DNS queries per run (default 60)
});
```

`systemResolver({ servers })` and `dohResolver({ endpoint })` are exported too.

## What is counted

The rules follow RFC 7208:

- Each `include`, `a`, `mx`, `ptr` and `exists` mechanism, and the `redirect` modifier, counts as **1 lookup**. Nested records are followed and added up.
- Evaluation stops at `all`, so **terms after `all` are not counted**. They are flagged, because they never take effect.
- **`redirect` is ignored when the record has an `all` mechanism** ([§6.1](https://www.rfc-editor.org/rfc/rfc7208#section-6.1)). It is flagged and not counted.
- If the same include is reached through two different branches, it counts **each time**, as receivers evaluate it each time. It is only a **loop** when an include points back to a record that is already being evaluated.
- A **void lookup** is one that returns NXDOMAIN or no records. For `a`, a name counts as void only if it has neither an A nor an AAAA record.
- An `include` or `redirect` to a domain that has no SPF record, or more than one, is an **error**: receivers return `permerror`.
- An `mx` that returns more than 10 MX records is an **error** ([§4.6.4](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4)).
- `+all` (or a bare `all`) is an **error**: it lets any server send mail as your domain.

### What is not counted

- **Macros** such as `%{i}` depend on who is sending. Those terms are counted, but the names behind them are not looked up, and the result is marked incomplete.
- **Address lookups behind `mx` and `ptr`.** For each MX host, receivers also look up its address. RFC 7208 limits those to 10 per `mx` term, separately from the main 10. This tool checks the count of MX records but does not look up each host. `ptr` needs the sender's IP address, so it is flagged as discouraged (§5.5) but not followed.
- **Message-level checks.** This is a DNS-only tool. It does not test whether a specific server or IP address would pass.

## Fixing a record that is over the limit

1. Run the tool and look at the `Lookups` column. The biggest numbers are the includes to tackle first.
2. Remove includes for services you no longer send mail through.
3. Replace `a` and `mx` with `ip4:` or `ip6:` ranges if your own servers rarely change. IP ranges cost no lookups.
4. Move a sending service to a subdomain with its own SPF record (for example `news.example.com`), if the provider supports a custom sending domain.
5. Be careful with "SPF flattening" services. They replace includes with IP lists, which need updating whenever a provider changes its IPs.

## Free website and email check

This tool is made by [Prime Dev Force](https://primedevforce.com). If you want SPF, DKIM, DMARC, TLS and security headers checked together in your browser, without installing anything, try the free [email security check](https://primedevforce.com/email-security-check).

## Licence

MIT. See [LICENSE](LICENSE).
