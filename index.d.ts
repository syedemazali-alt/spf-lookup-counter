export type RecordType = "TXT" | "A" | "AAAA" | "MX";

export interface DnsAnswer {
  /** "ok" with no records means the name exists but has no records of that type. */
  status: "ok" | "nxdomain" | "error";
  records: string[];
  detail?: string;
}

export interface SpfResolver {
  query(name: string, type: RecordType): Promise<DnsAnswer>;
}

export interface LookupNode {
  /** The SPF term, e.g. "include:_spf.google.com", or the domain at the root. */
  term: string;
  /** Lookups this term costs on its own (1 for a lookup term, 0 at the root). */
  lookups: number;
  /** Lookups this term costs including everything it pulls in. */
  total: number;
  /** For include and redirect: the domain followed and its SPF record. */
  domain?: string;
  record?: string | null;
  /** The lookup returned NXDOMAIN or no records. */
  void?: boolean;
  /** For a, mx and exists: how many records the lookup returned. */
  answers?: number;
  children: LookupNode[];
}

export interface SpfProblem {
  severity: "error" | "warning" | "incomplete";
  code: string;
  where: string;
  message: string;
}

export interface SpfLookupResult {
  domain: string;
  record: string | null;
  lookups: number;
  lookupLimit: number;
  voidLookups: number;
  voidLookupLimit: number;
  /** false when some lookups could not be made; counts are then a lower bound. */
  complete: boolean;
  /** true only when the count is complete and there are no errors. */
  ok: boolean;
  dnsQueries: number;
  tree: LookupNode;
  problems: SpfProblem[];
}

export interface CountOptions {
  resolver?: SpfResolver;
  /** Safety cap on DNS queries per run. Default 60. */
  maxQueries?: number;
}

export const LOOKUP_LIMIT: 10;
export const VOID_LOOKUP_LIMIT: 2;
export const MX_RECORD_LIMIT: 10;
export const DEFAULT_MAX_QUERIES: number;

export function countSpfLookups(domain: string, options?: CountOptions): Promise<SpfLookupResult>;
export function spfRecords(txt: string[]): string[];
export function parseSpf(record: string): {
  mechanisms: { qualifier: "+" | "-" | "~" | "?"; name: string; value?: string; raw: string }[];
  modifiers: { name: string; value: string; raw: string }[];
  invalid: string[];
};
export function isDomainName(domain: string): boolean;
export function parseTxtData(data: string): string;
export function systemResolver(options?: { servers?: string[]; timeoutMs?: number }): SpfResolver;
export function dohResolver(options?: { endpoint?: string; timeoutMs?: number; fetch?: typeof fetch }): SpfResolver;
