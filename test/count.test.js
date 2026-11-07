import { test } from "node:test";
import assert from "node:assert/strict";
import { countSpfLookups, parseSpf, parseTxtData, dohResolver } from "../src/index.js";

/** Fake DNS: zone[name][type] = records. Missing name → NXDOMAIN; missing type → no records. */
function fakeResolver(zone, { fail = [] } = {}) {
  const calls = [];
  return {
    calls,
    async query(name, type) {
      calls.push(`${name}|${type}`);
      if (fail.includes(name)) return { status: "error", records: [], detail: "SERVFAIL" };
      const z = zone[name];
      if (!z) return { status: "nxdomain", records: [] };
      return { status: "ok", records: z[type] ?? [] };
    },
  };
}

const codes = (r) => r.problems.map((p) => p.code).sort();
const ip = (s) => ({ TXT: [`v=spf1 ip4:${s} -all`] });

test("a simple record within limits", async () => {
  const resolver = fakeResolver({
    "a.test": { TXT: ["v=spf1 include:_spf.a.test mx -all"], MX: ["mx.a.test"] },
    "_spf.a.test": ip("192.0.2.1"),
  });
  const r = await countSpfLookups("A.test.", { resolver });
  assert.equal(r.domain, "a.test");
  assert.equal(r.lookups, 2);
  assert.equal(r.voidLookups, 0);
  assert.equal(r.complete, true);
  assert.equal(r.ok, true);
  assert.deepEqual(codes(r), []);
});

test("reports the exact count above 10, not just 'more than 10'", async () => {
  const zone = { "big.test": { TXT: [`v=spf1 ${Array.from({ length: 12 }, (_, i) => `include:s${i}.test`).join(" ")} -all`] } };
  for (let i = 0; i < 12; i++) zone[`s${i}.test`] = ip(`192.0.2.${i}`);
  const r = await countSpfLookups("big.test", { resolver: fakeResolver(zone) });
  assert.equal(r.lookups, 12);
  assert.equal(r.ok, false);
  assert.deepEqual(codes(r), ["too_many_lookups"]);
});

test("nested includes add up, and the tree shows the cost of each branch", async () => {
  const resolver = fakeResolver({
    "n.test": { TXT: ["v=spf1 include:one.test ip4:192.0.2.9 -all"] },
    "one.test": { TXT: ["v=spf1 include:two.test a ~all"], A: ["192.0.2.1"] },
    "two.test": { TXT: ["v=spf1 exists:x.two.test -all"] },
    "x.two.test": { A: ["127.0.0.2"] },
  });
  const r = await countSpfLookups("n.test", { resolver });
  assert.equal(r.lookups, 4);
  const one = r.tree.children[0];
  assert.equal(one.term, "include:one.test");
  assert.equal(one.total, 4);
  assert.equal(one.children[0].total, 2);
  assert.equal(one.children[0].record, "v=spf1 exists:x.two.test -all");
});

test("counts void lookups and flags more than 2", async () => {
  const resolver = fakeResolver({ "v.test": { TXT: ["v=spf1 a:gone1.test a:gone2.test mx:gone3.test -all"] } });
  const r = await countSpfLookups("v.test", { resolver });
  assert.equal(r.lookups, 3);
  assert.equal(r.voidLookups, 3);
  assert.deepEqual(codes(r), ["too_many_void_lookups"]);
});

test("an 'a' term with only an IPv6 address is not void", async () => {
  const resolver = fakeResolver({ "six.test": { TXT: ["v=spf1 a -all"], AAAA: ["2001:db8::1"] } });
  const r = await countSpfLookups("six.test", { resolver });
  assert.equal(r.voidLookups, 0);
  assert.equal(r.tree.children[0].answers, 1);
});

test("detects include loops", async () => {
  const resolver = fakeResolver({
    "l.test": { TXT: ["v=spf1 include:m.test -all"] },
    "m.test": { TXT: ["v=spf1 include:l.test -all"] },
  });
  const r = await countSpfLookups("l.test", { resolver });
  assert.deepEqual(codes(r), ["loop"]);
});

test("the same include in two branches counts twice and is not a loop", async () => {
  const resolver = fakeResolver({
    "d.test": { TXT: ["v=spf1 include:p.test include:q.test -all"] },
    "p.test": { TXT: ["v=spf1 include:shared.test -all"] },
    "q.test": { TXT: ["v=spf1 include:shared.test -all"] },
    "shared.test": ip("192.0.2.5"),
  });
  const r = await countSpfLookups("d.test", { resolver });
  assert.equal(r.lookups, 4);
  assert.deepEqual(codes(r), []);
  // The repeated name is queried once (cached), but counted on each evaluation.
  assert.equal(resolver.calls.filter((c) => c === "shared.test|TXT").length, 1);
});

test("terms after 'all' and a redirect next to 'all' are not counted", async () => {
  const resolver = fakeResolver({ "t.test": { TXT: ["v=spf1 ip4:192.0.2.1 -all include:late.test redirect=r.test"] } });
  const r = await countSpfLookups("t.test", { resolver });
  assert.equal(r.lookups, 0);
  assert.deepEqual(codes(r), ["redirect_ignored", "terms_after_all"]);
});

test("redirect counts when there is no 'all'", async () => {
  const resolver = fakeResolver({
    "r.test": { TXT: ["v=spf1 redirect=_spf.r.test"] },
    "_spf.r.test": { TXT: ["v=spf1 include:x.test -all"] },
    "x.test": ip("192.0.2.7"),
  });
  const r = await countSpfLookups("r.test", { resolver });
  assert.equal(r.lookups, 2);
  assert.deepEqual(codes(r), []);
});

test("an include of a domain without SPF is a permerror and a void lookup", async () => {
  const resolver = fakeResolver({ "i.test": { TXT: ["v=spf1 include:missing.test -all"] } });
  const r = await countSpfLookups("i.test", { resolver });
  assert.equal(r.voidLookups, 1);
  assert.deepEqual(codes(r), ["include_no_record"]);
});

test("macros make the result a lower bound", async () => {
  const resolver = fakeResolver({ "mac.test": { TXT: ["v=spf1 exists:%{i}.rbl.mac.test include:%{d}.x -all"] } });
  const r = await countSpfLookups("mac.test", { resolver });
  assert.equal(r.lookups, 2);
  assert.equal(r.complete, false);
  assert.equal(r.ok, false);
  assert.deepEqual(codes(r), ["macro_not_expanded", "macro_not_expanded"]);
});

test("a failed lookup is 'could not complete', never a pass", async () => {
  const resolver = fakeResolver({ "f.test": { TXT: ["v=spf1 include:broken.test -all"] } }, { fail: ["broken.test"] });
  const r = await countSpfLookups("f.test", { resolver });
  assert.equal(r.complete, false);
  assert.equal(r.ok, false);
  assert.deepEqual(codes(r), ["lookup_failed"]);
});

test("flags +all, a missing record and multiple records", async () => {
  const resolver = fakeResolver({
    "open.test": { TXT: ["v=spf1 ip6:2001:db8::/32 +all"] },
    "none.test": { TXT: ["google-site-verification=abc"] },
    "two.test": { TXT: ["v=spf1 -all", "v=spf1 ~all"] },
  });
  assert.deepEqual(codes(await countSpfLookups("open.test", { resolver })), ["pass_all"]);
  assert.deepEqual(codes(await countSpfLookups("none.test", { resolver })), ["no_record"]);
  assert.deepEqual(codes(await countSpfLookups("two.test", { resolver })), ["multiple_records"]);
});

test("more than 10 MX records for the mx mechanism is an error", async () => {
  const resolver = fakeResolver({ "mx.test": { TXT: ["v=spf1 mx -all"], MX: Array.from({ length: 11 }, (_, i) => `mx${i}.mx.test`) } });
  assert.deepEqual(codes(await countSpfLookups("mx.test", { resolver })), ["mx_too_many"]);
});

test("stops at the query cap and says so", async () => {
  const zone = { "cap.test": { TXT: [`v=spf1 ${Array.from({ length: 8 }, (_, i) => `include:c${i}.test`).join(" ")} -all`] } };
  for (let i = 0; i < 8; i++) zone[`c${i}.test`] = ip(`192.0.2.${i}`);
  const r = await countSpfLookups("cap.test", { resolver: fakeResolver(zone), maxQueries: 4 });
  assert.equal(r.dnsQueries, 4);
  assert.equal(r.complete, false);
  assert.ok(codes(r).includes("query_cap_reached"));
});

test("rejects things that are not domain names", async () => {
  await assert.rejects(countSpfLookups("not a domain", { resolver: fakeResolver({}) }), TypeError);
  await assert.rejects(countSpfLookups("http://x.test/", { resolver: fakeResolver({}) }), TypeError);
});

test("parser: syntax errors, qualifiers, CIDR suffixes and unknown modifiers", () => {
  const p = parseSpf("v=spf1 -a:mail.x.test/24 ~mx/24//64 ip6:2001:db8::/32 include: bogus foo=bar exp=e.x.test ?all");
  assert.deepEqual(p.invalid, ["include:", "bogus"]);
  assert.deepEqual(p.mechanisms.map((m) => [m.qualifier, m.name, m.value]), [
    ["-", "a", "mail.x.test"],
    ["~", "mx", undefined],
    ["+", "ip6", "2001:db8::"],
    ["?", "all", undefined],
  ]);
  assert.deepEqual(p.modifiers.map((m) => m.name), ["exp"]);
});

test("DoH: joins split TXT strings and maps NXDOMAIN", async () => {
  assert.equal(parseTxtData('"v=spf1 include:a.test" " -all"'), "v=spf1 include:a.test -all");
  const fetchImpl = async (url) => {
    const nx = url.includes("name=gone.test");
    const body = nx ? { Status: 3 } : { Status: 0, Answer: [{ type: 16, data: '"v=spf1 " "-all"' }, { type: 5, data: "alias." }] };
    return { ok: true, status: 200, json: async () => body };
  };
  const doh = dohResolver({ fetch: fetchImpl });
  assert.deepEqual(await doh.query("x.test", "TXT"), { status: "ok", records: ["v=spf1 -all"] });
  assert.deepEqual(await doh.query("gone.test", "TXT"), { status: "nxdomain", records: [] });
});
