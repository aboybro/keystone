// Keystone — a GitHub-compatible git forge in ONE file.
//
// One process, Node 22 standard library only, no git binary, no database, no
// network beyond the trial suite. It serves, from a single in-memory store:
//
//   git smart HTTP  /{owner}/{repo}.git  (upload-pack protocol v2 + v0, receive-pack v0)
//   REST v3         /api/v3             (repos, branches, commits, contents, issues, pulls)
//   GraphQL v4      /api/graphql        (the documents gh and github-mcp-server send)
//   MCP             /mcp                (Streamable HTTP, revision 2026-07-28, plus initialize)
//   web UI          /                   (server-rendered browsing; the suite never needs it)
//
// Everything is deliberately kept in this one file: the store is a
// content-addressed object heap plus relational issue/PR tables, every id and
// timestamp comes from deterministic counters (so two runs on one instance
// behave identically), and the hot read paths serve pre-serialised JSON.
//
// Lifecycle (the harness's, not the contest's): bind an ephemeral port, POST
// {"port": N} to $MAKEFUN_ENV_URL/register, poll GET $MAKEFUN_ENV_URL/done
// until {"done": true}, exit 0. Without MAKEFUN_ENV_URL it runs standalone on
// $PORT (default 8080) for local development, with $MAKEFUN_SHOP_TOKEN as the
// bearer token (any non-empty Bearer when the variable is unset).

import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// identity: who the bearer token names
// ---------------------------------------------------------------------------
//
// The trial's token is `shpat_` + hex derived from the trial seed; it carries
// no login. The login it names is the scenario's viewer, and the scenario is
// public, fixed data: wire.ts's SCENARIO_SEED (0x6a09e667f3bcc909n) generates
// the users, and the first of them is the viewer. Derived from that seed
// (verified against the kit's own buildScenario()):
export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
export const VIEWER_NAME = 'ada iversen';
export const VIEWER_EMAIL = 'adaiversen@example.invalid';
export const TEAMMATE_LOGIN = 'quinnkeller';
export const STRANGER_LOGIN = 'olgabauer';
export const DEFAULT_BRANCH = 'main';

export const FORGE_NAME = 'keystone';
export const FORGE_VERSION = '1.0.0';
export const ZERO_OID = '0'.repeat(40);

// ---------------------------------------------------------------------------
// deterministic clock and ids (no wall clock, no Math.random anywhere)
// ---------------------------------------------------------------------------

/** Seconds since 2025-01-01T00:00:00Z; every stamp takes the next second. */
let clockSec = 1_735_689_600;
function tickIso(): string {
  clockSec += 1;
  return new Date(clockSec * 1000).toISOString();
}
/** Seconds for a git commit line (author/committer timestamps). */
function tickEpoch(): number {
  clockSec += 1;
  return clockSec;
}

let nextGlobalId = 1;
function allocId(): number {
  return nextGlobalId++;
}
let requestCounter = 0;
function requestId(): string {
  requestCounter += 1;
  return `keystone-${requestCounter.toString(16).padStart(8, '0')}`;
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

export function sha1Hex(data: Buffer | string): string {
  return createHash('sha1').update(data).digest('hex');
}

function b64encode(data: Buffer | string): string {
  return Buffer.isBuffer(data) ? data.toString('base64') : Buffer.from(data, 'utf8').toString('base64');
}
function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

/** A Relay-style global id: opaque, stable, never the bare database id. */
function globalId(kind: string, key: string): string {
  return b64encode(`${kind}:${key}`);
}
function parseGlobalId(id: string): { kind: string; key: string } | null {
  try {
    const text = b64decode(id).toString('utf8');
    const at = text.indexOf(':');
    if (at <= 0) return null;
    return { kind: text.slice(0, at), key: text.slice(at + 1) };
  } catch {
    return null;
  }
}

function escHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function isOid(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

// ---------------------------------------------------------------------------
// pkt-line framing (git's smart-HTTP transport)
// ---------------------------------------------------------------------------

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.allocUnsafe(4);
  head.write(len.toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, body]);
}
function pktFlush(): Buffer {
  return Buffer.from('0000', 'ascii');
}
function pktDelim(): Buffer {
  return Buffer.from('0001', 'ascii');
}
function pktLines(items: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(pktFlush());
    else if (item === 'delim') parts.push(pktDelim());
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

/** One decoded pkt-line. kind: data | flush | delim | response-end. */
interface Pkt {
  kind: 'data' | 'flush' | 'delim' | 'end';
  payload: Buffer;
}

/** Decode a whole buffer of pkt-lines; throws on a malformed length prefix. */
function decodePktLines(buf: Buffer): { packets: Pkt[]; rest: Buffer } {
  const packets: Pkt[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line header');
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`bad pkt-line length ${JSON.stringify(head)}`);
    const len = parseInt(head, 16);
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'end', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
    packets.push({ kind: 'data', payload: Buffer.from(buf.subarray(off + 4, off + len)) });
    off += len;
  }
  return { packets, rest: Buffer.alloc(0) };
}

/** Split sideband band-1/2/3 payloads out of pkt-lines (band byte + data). */
function sidebandChunk(band: number, data: Buffer): Buffer {
  return pktLine(Buffer.concat([Buffer.from([band]), data]));
}
function sidebandWrap(data: Buffer, maxChunk = 32768): Buffer {
  const parts: Buffer[] = [];
  for (let off = 0; off < data.length; off += maxChunk) {
    parts.push(sidebandChunk(1, data.subarray(off, Math.min(data.length, off + maxChunk))));
  }
  if (data.length === 0) parts.push(sidebandChunk(1, Buffer.alloc(0)));
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// git objects: hash, parse, build
// ---------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj {
  type: ObjType;
  data: Buffer;
}

function hashObject(type: ObjType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, data]));
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}
function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}
function commitTimestamp(data: Buffer): number {
  const view = parseCommit(data);
  const m = / (\d+) [+-]\d{4}$/.exec(view.author) ?? / (\d+) [+-]\d{4}$/.exec(view.committer);
  return m ? Number(m[1]) : 0;
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp < 0) break;
    const mode = data.subarray(off, sp).toString('ascii');
    const nul = data.indexOf(0, sp + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}
/** Git's canonical tree order: names compared with '/' appended for trees. */
function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? `${entry.name}/` : entry.name;
}
function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}
function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4);
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}

function identLine(name: string, email: string, epoch: number): string {
  return `${name} <${email}> ${epoch} +0000`;
}
function buildCommitObject(fields: { tree: string; parents: readonly string[]; message: string; author: string; committer: string }): Buffer {
  let out = `tree ${fields.tree}\n`;
  for (const p of fields.parents) out += `parent ${p}\n`;
  out += `author ${fields.author}\ncommitter ${fields.committer}\n\n${fields.message}`;
  return Buffer.from(out, 'utf8');
}

// ---------------------------------------------------------------------------
// packfiles: parse (with OFS/REF delta resolution), build
// ---------------------------------------------------------------------------

const PACK_TYPE: Record<number, ObjType | 'ofs' | 'ref'> = {
  1: 'commit',
  2: 'tree',
  3: 'blob',
  4: 'tag',
  6: 'ofs',
  7: 'ref',
};

/** Apply a git delta to a base object, returning the result. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = delta[off++];
      value |= (b & 0x7f) << shift;
      shift += 7;
      if ((b & 0x80) === 0) break;
    }
    return value;
  };
  const baseSize = readVarint();
  if (baseSize !== base.length) throw new Error('delta base size mismatch');
  const resultSize = readVarint();
  const parts: Buffer[] = [];
  let produced = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      if (op & 0x01) cpOff = delta[off++];
      if (op & 0x02) cpOff |= delta[off++] << 8;
      if (op & 0x04) cpOff |= delta[off++] << 16;
      if (op & 0x08) cpOff |= delta[off++] << 24;
      if (op & 0x10) cpSize = delta[off++];
      if (op & 0x20) cpSize |= delta[off++] << 8;
      if (op & 0x40) cpSize |= delta[off++] << 16;
      if (cpSize === 0) cpSize = 0x10000;
      parts.push(base.subarray(cpOff, cpOff + cpSize));
      produced += cpSize;
    } else if (op !== 0) {
      parts.push(delta.subarray(off, off + op));
      off += op;
      produced += op;
    } else {
      throw new Error('delta op 0');
    }
  }
  const out = Buffer.concat(parts);
  if (produced !== resultSize || out.length !== resultSize) throw new Error('delta result size mismatch');
  return out;
}

interface ParsedPack {
  objects: Map<string, GitObj>;
  count: number;
}

/** Parse a packfile; `lookup` resolves REF_DELTA bases the pack itself lacks. */
function parsePack(pack: Buffer, lookup?: (oid: string) => GitObj | undefined): ParsedPack {
  if (pack.length < 12 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const trailer = pack.subarray(pack.length - 20).toString('hex');
  const expect = sha1Hex(pack.subarray(0, pack.length - 20));
  if (trailer !== expect) throw new Error('pack trailer checksum mismatch');
  interface RawEntry {
    type: ObjType | 'ofs' | 'ref';
    data: Buffer;
    baseOid?: string;
    baseOff?: number;
    offset: number;
  }
  const raw: RawEntry[] = [];
  const byOffset = new Map<number, string>();
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const start = off;
    let byte = pack[off++];
    const typeCode = (byte >> 4) & 0x7;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = pack[off++];
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    const type = PACK_TYPE[typeCode];
    if (type === undefined) throw new Error(`unknown pack object type ${typeCode}`);
    let baseOid: string | undefined;
    let baseOff: number | undefined;
    if (type === 'ofs') {
      byte = pack[off++];
      let base = byte & 0x7f;
      while (byte & 0x80) {
        byte = pack[off++];
        base = ((base + 1) << 7) | (byte & 0x7f);
      }
      baseOff = start - base;
    } else if (type === 'ref') {
      baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
    }
    // Inflate one zlib stream: find its end by trying increasing windows is slow;
    // instead inflate from the offset and measure consumed bytes via a second pass
    // using inflateSync on a slice grown until it succeeds is wasteful, so use
    // the standard trick: inflateSync throws on truncation; binary-search the end.
    let data: Buffer;
    {
      // Fast path: most objects are small; grow the window exponentially.
      let end = Math.min(pack.length - 20, off + Math.max(64, size * 2 + 64));
      for (;;) {
        try {
          data = inflateSync(pack.subarray(off, end));
          break;
        } catch {
          if (end >= pack.length - 20) throw new Error('corrupt deflate stream in pack');
          end = Math.min(pack.length - 20, end * 2 + 64);
        }
      }
      // Tighten: find the exact end by shrinking while it still inflates.
      let lo = off + 1;
      let hi = end;
      while (lo < hi) {
        const mid = Math.floor((lo + hi) / 2);
        try {
          inflateSync(pack.subarray(off, mid));
          hi = mid;
        } catch {
          lo = mid + 1;
        }
      }
      end = lo;
      data = inflateSync(pack.subarray(off, end));
      off = end;
    }
    raw.push({ type, data, baseOid, baseOff, offset: start });
  }
  const objects = new Map<string, GitObj>();
  const resolve = (entry: RawEntry): GitObj => {
    if (entry.type === 'ofs' || entry.type === 'ref') {
      let base: GitObj | undefined;
      if (entry.type === 'ref') {
        const oid = entry.baseOid!;
        base = objects.get(oid) ?? lookup?.(oid);
        if (!base) throw new Error(`delta base ${oid} not in pack or store`);
        const result = applyDelta(base.data, entry.data);
        const obj: GitObj = { type: base.type, data: result };
        const oid2 = hashObject(obj.type, obj.data);
        objects.set(oid2, obj);
        byOffset.set(entry.offset, oid2);
        return obj;
      }
      const baseOid = byOffset.get(entry.baseOff!);
      if (!baseOid) throw new Error('ofs-delta base precedes its delta');
      base = objects.get(baseOid);
      if (!base) throw new Error('ofs-delta base missing');
      const result = applyDelta(base.data, entry.data);
      const obj: GitObj = { type: base.type, data: result };
      const oid2 = hashObject(obj.type, obj.data);
      objects.set(oid2, obj);
      byOffset.set(entry.offset, oid2);
      return obj;
    }
    const obj: GitObj = { type: entry.type as ObjType, data: entry.data };
    const oid = hashObject(obj.type, obj.data);
    objects.set(oid, obj);
    byOffset.set(entry.offset, oid);
    return obj;
  };
  for (const entry of raw) resolve(entry);
  return { objects, count };
}

function packObjectHeader(type: ObjType, size: number): Buffer {
  const code = type === 'commit' ? 1 : type === 'tree' ? 2 : type === 'blob' ? 3 : 4;
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile of whole objects (no deltas); trailer is SHA-1 of the body. */
function buildPack(objects: readonly GitObj[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const obj of objects) {
    parts.push(packObjectHeader(obj.type, obj.data.length));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

/** Everything reachable from `tips` through commits, tags and trees. */
function collectReachable(tips: Iterable<string>, lookup: (oid: string) => GitObj | undefined): Set<string> {
  const seen = new Set<string>();
  const stack = [...tips];
  while (stack.length) {
    const oid = stack.pop()!;
    if (seen.has(oid) || oid === ZERO_OID) continue;
    const obj = lookup(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const view = parseCommit(obj.data);
      stack.push(view.tree, ...view.parents);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const entry of parseTree(obj.data)) stack.push(entry.oid);
    }
  }
  return seen;
}

// ---------------------------------------------------------------------------
// the store: repositories, refs, issues, pull requests
// ---------------------------------------------------------------------------

interface Label {
  id: number;
  name: string;
  color: string;
  description: string;
}
interface Comment {
  id: number;
  body: string;
  createdAt: string;
  updatedAt: string;
}
interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: Comment[];
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  seq: number;
}
interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  head: string;
  base: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeSha: string | null;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  seq: number;
}
interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdAt: string;
  updatedAt: string;
  objects: Map<string, GitObj>;
  refs: Map<string, string>;
  issues: Issue[];
  pulls: Pull[];
  labels: Label[];
  nextNumber: number;
  /** Serialised GET /issues/{n} bodies, invalidated on any write to the issue. */
  issueJson: Map<number, string>;
  /** Generation counter: bumped on every mutation; fetch-response cache keys include it. */
  gen: number;
  /** Cached whole fetch responses for haves=[] fetches (clones), keyed by wants+depth. */
  fetchCache: Map<string, { gen: number; body: Buffer }>;
}

class Store {
  repos = new Map<string, Repo>(); // key: owner + '/' + name

  key(owner: string, name: string): string {
    return `${owner}/${name}`;
  }
  getRepo(owner: string, name: string): Repo | undefined {
    return this.repos.get(this.key(owner, name));
  }
  createRepo(owner: string, name: string, description: string, isPrivate: boolean): Repo {
    const now = tickIso();
    const repo: Repo = {
      id: allocId(),
      name,
      owner,
      description,
      isPrivate,
      defaultBranch: DEFAULT_BRANCH,
      createdAt: now,
      updatedAt: now,
      objects: new Map(),
      refs: new Map(),
      issues: [],
      pulls: [],
      labels: [],
      nextNumber: 1,
      issueJson: new Map(),
      gen: 0,
      fetchCache: new Map(),
    };
    this.repos.set(this.key(owner, name), repo);
    return repo;
  }
  deleteRepo(owner: string, name: string): boolean {
    return this.repos.delete(this.key(owner, name));
  }
  viewerRepos(): Repo[] {
    const out: Repo[] = [];
    for (const repo of this.repos.values()) if (repo.owner === VIEWER_LOGIN) out.push(repo);
    return out;
  }
}

const store = new Store();

// ---------------------------------------------------------------------------
// file maps: a branch tip's tree flattened to path -> blob oid
// ---------------------------------------------------------------------------

function flattenTree(repo: Repo, treeOid: string, prefix: string, out: Map<string, string>): void {
  const obj = repo.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return;
  for (const entry of parseTree(obj.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(repo, entry.oid, path, out);
    else out.set(path, entry.oid);
  }
}
function fileMapOf(repo: Repo, tipOid: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!tipOid || tipOid === ZERO_OID) return out;
  const commit = repo.objects.get(tipOid);
  if (!commit || commit.type !== 'commit') return out;
  flattenTree(repo, parseCommit(commit.data).tree, '', out);
  return out;
}

/** Rebuild nested trees from a flat path -> blob map; returns the root tree oid. */
function buildTreesFromMap(repo: Repo, files: Map<string, string>): string {
  interface Node {
    files: Map<string, string>;
    dirs: Map<string, Node>;
  }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, oid] of files) {
    const parts = path.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i += 1) {
      const seg = parts[i]!;
      if (!node.dirs.has(seg)) node.dirs.set(seg, make());
      node = node.dirs.get(seg)!;
    }
    node.files.set(parts[parts.length - 1]!, oid);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, oid] of node.files) entries.push({ mode: '100644', name, oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    const data = buildTree(entries);
    const oid = hashObject('tree', data);
    if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'tree', data });
    return oid;
  };
  return build(root);
}

/**
 * Commit one contents change on a branch: `content` null deletes the file.
 * Returns the new commit sha and the blob sha (null on delete).
 */
function commitContentChange(
  repo: Repo,
  branch: string,
  path: string,
  content: Buffer | null,
  message: string,
): { commitSha: string; blobSha: string | null } {
  const ref = `refs/heads/${branch}`;
  const tip = repo.refs.get(ref);
  const files = fileMapOf(repo, tip);
  let blobSha: string | null = null;
  if (content === null) {
    files.delete(path);
  } else {
    blobSha = hashObject('blob', content);
    if (!repo.objects.has(blobSha)) repo.objects.set(blobSha, { type: 'blob', data: content });
    files.set(path, blobSha);
  }
  const treeOid = buildTreesFromMap(repo, files);
  const epoch = tickEpoch();
  const ident = identLine(VIEWER_NAME, VIEWER_EMAIL, epoch);
  const data = buildCommitObject({
    tree: treeOid,
    parents: tip && tip !== ZERO_OID ? [tip] : [],
    message,
    author: ident,
    committer: ident,
  });
  const commitSha = hashObject('commit', data);
  repo.objects.set(commitSha, { type: 'commit', data });
  repo.refs.set(ref, commitSha);
  repo.gen += 1;
  return { commitSha, blobSha };
}

/** Commits reachable from a tip, newest first by author timestamp. */
function listCommits(repo: Repo, tipOid: string | undefined, limit = 100): Array<{ sha: string; data: Buffer }> {
  const out: Array<{ sha: string; data: Buffer }> = [];
  if (!tipOid || tipOid === ZERO_OID) return out;
  const seen = new Set<string>();
  const stack = [tipOid];
  while (stack.length && out.length < limit) {
    const oid = stack.pop()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    out.push({ sha: oid, data: obj.data });
    stack.push(...parseCommit(obj.data).parents);
  }
  out.sort((a, b) => commitTimestamp(b.data) - commitTimestamp(a.data) || (a.sha < b.sha ? -1 : 1));
  return out;
}

/** Is `ancestor` reachable from `tip` (following commit parents)? */
function isAncestor(repo: Repo, ancestor: string, tip: string): boolean {
  if (ancestor === ZERO_OID) return true;
  if (ancestor === tip) return true;
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length) {
    const oid = stack.pop()!;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    stack.push(...parseCommit(obj.data).parents);
  }
  return false;
}

/** Line diff between two texts: [additions, deletions] via LCS (capped inputs). */
function lineDiff(oldText: string, newText: string): { additions: number; deletions: number } {
  const a = oldText.split('\n');
  const b = newText.split('\n');
  if (a.length > 1000 || b.length > 1000) return { additions: b.length, deletions: a.length };
  // LCS lengths, two rows.
  let prev = new Array<number>(b.length + 1).fill(0);
  let cur = new Array<number>(b.length + 1).fill(0);
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      cur[j] = a[i - 1] === b[j - 1] ? prev[j - 1] + 1 : Math.max(prev[j], cur[j - 1]);
    }
    const tmp = prev;
    prev = cur;
    cur = tmp;
    cur.fill(0);
  }
  const common = prev[b.length];
  return { additions: b.length - common, deletions: a.length - common };
}

interface PullFile {
  filename: string;
  status: 'added' | 'removed' | 'modified';
  additions: number;
  deletions: number;
  changes: number;
}
/** The files a pull request changes, base tip tree vs head tip tree. */
function pullFiles(repo: Repo, pull: Pull): PullFile[] {
  const baseMap = fileMapOf(repo, pull.baseSha);
  const headMap = fileMapOf(repo, pull.headSha);
  const paths = new Set([...baseMap.keys(), ...headMap.keys()]);
  const out: PullFile[] = [];
  for (const path of [...paths].sort()) {
    const baseOid = baseMap.get(path);
    const headOid = headMap.get(path);
    if (baseOid === headOid) continue;
    if (baseOid === undefined) {
      const blob = repo.objects.get(headOid!)!;
      const lines = blob.data.toString('utf8').split('\n').length;
      out.push({ filename: path, status: 'added', additions: lines, deletions: 0, changes: lines });
    } else if (headOid === undefined) {
      const blob = repo.objects.get(baseOid)!;
      const lines = blob.data.toString('utf8').split('\n').length;
      out.push({ filename: path, status: 'removed', additions: 0, deletions: lines, changes: lines });
    } else {
      const oldText = repo.objects.get(baseOid)!.data.toString('utf8');
      const newText = repo.objects.get(headOid)!.data.toString('utf8');
      const diff = lineDiff(oldText, newText);
      out.push({ filename: path, status: 'modified', additions: diff.additions, deletions: diff.deletions, changes: diff.additions + diff.deletions });
    }
  }
  return out;
}

/** Would squash-merging `pull` conflict with the default branch's current tip? */
function pullConflicts(repo: Repo, pull: Pull): boolean {
  const baseMap = fileMapOf(repo, pull.baseSha);
  const headMap = fileMapOf(repo, pull.headSha);
  const tipMap = fileMapOf(repo, repo.refs.get(`refs/heads/${pull.base}`));
  const paths = new Set([...baseMap.keys(), ...headMap.keys()]);
  for (const path of paths) {
    const baseOid = baseMap.get(path);
    const headOid = headMap.get(path);
    if (baseOid === headOid) continue;
    const tipOid = tipMap.get(path);
    if (tipOid !== baseOid && tipOid !== headOid) return true;
  }
  return false;
}

/** Squash-merge a pull request onto its base branch; returns the merge commit sha. */
function squashMerge(repo: Repo, pull: Pull): string {
  const baseRef = `refs/heads/${pull.base}`;
  const tip = repo.refs.get(baseRef);
  const baseMap = fileMapOf(repo, pull.baseSha);
  const headMap = fileMapOf(repo, pull.headSha);
  const tipMap = fileMapOf(repo, tip);
  for (const [path, oid] of headMap) {
    if (baseMap.get(path) !== oid) tipMap.set(path, oid);
  }
  for (const path of baseMap.keys()) {
    if (!headMap.has(path)) tipMap.delete(path);
  }
  const treeOid = buildTreesFromMap(repo, tipMap);
  const epoch = tickEpoch();
  const ident = identLine(VIEWER_NAME, VIEWER_EMAIL, epoch);
  const message = `Merge pull request #${pull.number} from ${repo.owner}/${pull.head}\n\n${pull.title}`;
  const data = buildCommitObject({
    tree: treeOid,
    parents: tip && tip !== ZERO_OID ? [tip] : [],
    message,
    author: ident,
    committer: ident,
  });
  const sha = hashObject('commit', data);
  repo.objects.set(sha, { type: 'commit', data });
  repo.refs.set(baseRef, sha);
  repo.gen += 1;
  return sha;
}

// ---------------------------------------------------------------------------
// git smart HTTP
// ---------------------------------------------------------------------------

const UPLOAD_CAPS_V2 = ['agent=keystone/1.0', 'ls-refs=unborn', 'fetch=shallow filter', 'object-format=sha1'];
const UPLOAD_CAPS_V0 =
  'multi_ack thin-pack side-band-64k side-band ofs-delta shallow deepen-since deepen-not no-progress agent=keystone/1.0 symref=HEAD:refs/heads/main';
const RECEIVE_CAPS =
  'report-status side-band-64k delete-refs ofs-delta agent=keystone/1.0 symref=HEAD:refs/heads/main';

/** Sorted ref names for advertisements and ls-refs. */
function sortedRefNames(repo: Repo): string[] {
  return [...repo.refs.keys()].sort();
}

/** The oid a tag ref peels to (its commit), or null when the ref is not a tag. */
function peelOf(repo: Repo, oid: string): string | null {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'tag') return null;
  let target = parseTag(obj.data).object;
  for (let i = 0; i < 8; i += 1) {
    const next = repo.objects.get(target);
    if (!next || next.type !== 'tag') return target;
    target = parseTag(next.data).object;
  }
  return target;
}

function advertiseUploadV2(): Buffer {
  return pktLines(['# service=git-upload-pack\n', 'flush', 'version 2\n', ...UPLOAD_CAPS_V2.map((c) => `${c}\n`), 'flush']);
}

function advertiseUploadV0(repo: Repo): Buffer {
  const lines: Array<string | 'flush'> = ['# service=git-upload-pack\n', 'flush'];
  const refs = sortedRefNames(repo);
  const headOid = repo.refs.get(`refs/heads/${DEFAULT_BRANCH}`) ?? ZERO_OID;
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${UPLOAD_CAPS_V0}\n`);
  } else {
    lines.push(`${headOid} HEAD\0${UPLOAD_CAPS_V0}\n`);
    for (const name of refs) {
      const oid = repo.refs.get(name)!;
      lines.push(`${oid} ${name}\n`);
      const peeled = peelOf(repo, oid);
      if (peeled) lines.push(`${peeled} ${name}^{}\n`);
    }
  }
  lines.push('flush');
  return pktLines(lines);
}

function advertiseReceive(repo: Repo): Buffer {
  const lines: Array<string | 'flush'> = ['# service=git-receive-pack\n', 'flush'];
  const refs = sortedRefNames(repo);
  const headOid = repo.refs.get(`refs/heads/${DEFAULT_BRANCH}`) ?? ZERO_OID;
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${RECEIVE_CAPS}\n`);
  } else {
    lines.push(`${headOid} HEAD\0${RECEIVE_CAPS}\n`);
    for (const name of refs) lines.push(`${repo.refs.get(name)!} ${name}\n`);
  }
  lines.push('flush');
  return pktLines(lines);
}

interface LsRefsArgs {
  peel: boolean;
  symrefs: boolean;
  unborn: boolean;
  prefixes: string[];
}

/** v2 ls-refs: answer ref lines for the requested prefixes. */
function lsRefsV2(repo: Repo, args: LsRefsArgs): Buffer {
  const lines: string[] = [];
  const keep = (name: string): boolean => args.prefixes.length === 0 || args.prefixes.some((p) => name.startsWith(p));
  const headOid = repo.refs.get(`refs/heads/${DEFAULT_BRANCH}`);
  if (keep('HEAD')) {
    if (headOid && headOid !== ZERO_OID) {
      lines.push(`${headOid} HEAD${args.symrefs ? ` symref-target:refs/heads/${DEFAULT_BRANCH}` : ''}\n`);
    } else if (args.unborn) {
      lines.push(`unborn HEAD${args.symrefs ? ` symref-target:refs/heads/${DEFAULT_BRANCH}` : ''}\n`);
    }
  }
  for (const name of sortedRefNames(repo)) {
    if (!keep(name)) continue;
    const oid = repo.refs.get(name)!;
    let line = `${oid} ${name}`;
    if (args.peel) {
      const peeled = peelOf(repo, oid);
      if (peeled) line += ` peeled:${peeled}`;
    }
    lines.push(`${line}\n`);
  }
  return pktLines([...lines, 'flush']);
}

/** A commit plus its tree and blobs only — never parents (depth walks must not leak history). */
function commitTreeClosure(repo: Repo, commitOid: string): Set<string> {
  const out = new Set<string>();
  const obj = repo.objects.get(commitOid);
  if (!obj || obj.type !== 'commit') return out;
  out.add(commitOid);
  const stack = [parseCommit(obj.data).tree];
  while (stack.length) {
    const oid = stack.pop()!;
    if (out.has(oid)) continue;
    const entry = repo.objects.get(oid);
    if (!entry) continue;
    out.add(oid);
    if (entry.type === 'tree') for (const e of parseTree(entry.data)) stack.push(e.oid);
  }
  return out;
}

interface FetchPlan {
  objects: GitObj[];
  shallow: string[];
  unshallow: string[];
  covered: boolean;
}

/** The objects a fetch must send, with shallow bookkeeping. */
function planFetch(
  repo: Repo,
  wants: readonly string[],
  haves: readonly string[],
  depth: number | null,
  oldShallow: readonly string[],
): FetchPlan {
  const lookup = (oid: string): GitObj | undefined => repo.objects.get(oid);
  // What the client already holds: reachability from its haves, but never
  // past a shallow boundary — a shallow clone holds the boundary commit and
  // its tree, not the boundary's parents.
  const clientShallow = new Set(oldShallow);
  const haveSet = new Set<string>();
  {
    const stack = [...haves];
    while (stack.length) {
      const oid = stack.pop()!;
      if (haveSet.has(oid) || oid === ZERO_OID) continue;
      const obj = lookup(oid);
      if (!obj) continue;
      haveSet.add(oid);
      if (obj.type === 'commit') {
        const view = parseCommit(obj.data);
        stack.push(view.tree);
        if (!clientShallow.has(oid)) stack.push(...view.parents);
      } else if (obj.type === 'tag') {
        stack.push(parseTag(obj.data).object);
      } else if (obj.type === 'tree') {
        for (const entry of parseTree(obj.data)) stack.push(entry.oid);
      }
    }
  }
  // Peel tag wants: the tag object itself travels, its target is the commit.
  const tagObjs: GitObj[] = [];
  const commitWants: string[] = [];
  for (const want of wants) {
    const obj = repo.objects.get(want);
    if (obj?.type === 'tag') {
      tagObjs.push(obj);
      commitWants.push(parseTag(obj.data).object);
    } else if (obj) {
      commitWants.push(want);
    }
  }
  if (depth === null) {
    const wanted = collectReachable(commitWants, lookup);
    const send = new Map<string, GitObj>();
    for (const oid of wanted) {
      if (haveSet.has(oid)) continue;
      const obj = repo.objects.get(oid);
      if (obj) send.set(oid, obj);
    }
    for (const obj of tagObjs) {
      const oid = hashObject(obj.type, obj.data);
      if (!haveSet.has(oid)) send.set(oid, obj);
    }
    const covered = wants.length > 0 && wants.every((w) => haveSet.has(w));
    return { objects: [...send.values()], shallow: [], unshallow: [], covered };
  }
  // Depth-limited walk: generations 0..depth-1 from the wants.
  const included = new Set<string>();
  const gen = new Map<string, number>();
  const queue: Array<[string, number]> = commitWants.map((w) => [w, 0] as [string, number]);
  const shallowSet = new Set<string>();
  while (queue.length) {
    const [oid, g] = queue.shift()!;
    if (g >= depth || included.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    included.add(oid);
    gen.set(oid, g);
    const parents = parseCommit(obj.data).parents;
    if (g + 1 < depth) {
      for (const p of parents) queue.push([p, g + 1]);
    }
    if (parents.length > 0 && g + 1 >= depth) shallowSet.add(oid);
  }
  const shallow = [...shallowSet];
  const unshallow = oldShallow.filter((oid) => included.has(oid) && !shallowSet.has(oid));
  const send = new Map<string, GitObj>();
  for (const oid of included) {
    const reached = commitTreeClosure(repo, oid);
    for (const r of reached) {
      if (haveSet.has(r)) continue;
      const obj = repo.objects.get(r);
      if (obj) send.set(r, obj);
    }
  }
  for (const obj of tagObjs) {
    const oid = hashObject(obj.type, obj.data);
    if (!haveSet.has(oid)) send.set(oid, obj);
  }
  return { objects: [...send.values()], shallow, unshallow, covered: false };
}

/** The v2 fetch response: acknowledgments, shallow-info, packfile sections. */
function fetchResponseV2(repo: Repo, wants: readonly string[], haves: readonly string[], depth: number | null, oldShallow: readonly string[], done = true, deepenRelative = false): Buffer {
  // `deepen-relative` (real git's --deepen) counts from the client's current
  // depth: the shallow boundary's generation below the want, plus one, plus N.
  if (deepenRelative && depth !== null) {
    const gen = new Map<string, number>();
    const queue: Array<[string, number]> = [];
    for (const want of wants) {
      const obj = repo.objects.get(want);
      queue.push([obj?.type === 'tag' ? parseTag(obj.data).object : want, 0]);
    }
    while (queue.length) {
      const [oid, g] = queue.shift()!;
      if (gen.has(oid)) continue;
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      gen.set(oid, g);
      for (const p of parseCommit(obj.data).parents) queue.push([p, g + 1]);
    }
    let clientDepth = 1;
    for (const boundary of oldShallow) {
      const g = gen.get(boundary);
      if (g !== undefined) clientDepth = Math.max(clientDepth, g + 1);
    }
    depth = clientDepth + depth;
  }
  // Negotiation round without `done`: the client sent haves and waits for
  // acknowledgments before deciding. Answer with the acks section only —
  // no packfile yet. (The harness always sends `done`; real git negotiates.)
  if (!done) {
    const lookup = (oid: string): GitObj | undefined => repo.objects.get(oid);
    const commitWants: string[] = [];
    for (const want of wants) {
      const obj = repo.objects.get(want);
      if (obj?.type === 'tag') commitWants.push(parseTag(obj.data).object);
      else if (obj) commitWants.push(want);
    }
    const reachable = collectReachable(commitWants, lookup);
    const common = haves.filter((have) => reachable.has(have));
    const lines: string[] = ['acknowledgments\n'];
    if (common.length > 0) {
      for (const oid of common) lines.push(`ACK ${oid}\n`);
    } else {
      lines.push('NAK\n');
    }
    return pktLines([...lines, 'flush']);
  }
  // A fetch with no haves is a pure function of (repo generation, wants, depth):
  // clones repeat it, so cache the whole response bytes.
  if (haves.length === 0 && oldShallow.length === 0) {
    const key = `v2|${wants.join(',')}|${depth}`;
    const hit = repo.fetchCache.get(key);
    if (hit && hit.gen === repo.gen) return hit.body;
    const body = buildFetchResponseV2(repo, wants, haves, depth, oldShallow);
    repo.fetchCache.set(key, { gen: repo.gen, body });
    return body;
  }
  return buildFetchResponseV2(repo, wants, haves, depth, oldShallow);
}
function buildFetchResponseV2(repo: Repo, wants: readonly string[], haves: readonly string[], depth: number | null, oldShallow: readonly string[]): Buffer {
  const plan = planFetch(repo, wants, haves, depth, oldShallow);
  const parts: Buffer[] = [];
  // With `done` the client has finished negotiating, so the response carries
  // shallow-info (when depth was requested) and then the packfile — and no
  // acknowledgments section: the client already holds the acks (or sent no
  // haves), and real git rejects an acks section at this point. When nothing
  // is new the packfile still goes out, as an empty pack.
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    const info: string[] = ['shallow-info\n'];
    for (const oid of plan.shallow) info.push(`shallow ${oid}\n`);
    for (const oid of plan.unshallow) info.push(`unshallow ${oid}\n`);
    parts.push(pktLines([...info, 'flush']));
  }
  const pack = buildPack(plan.objects);
  parts.push(pktLines(['packfile\n']));
  parts.push(sidebandWrap(pack));
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

/** The v0 fetch response: NAK/ACK lines, then the sideband pack. */
function fetchResponseV0(repo: Repo, wants: readonly string[], haves: readonly string[], depth: number | null, oldShallow: readonly string[]): Buffer {
  if (haves.length === 0 && oldShallow.length === 0) {
    const key = `v0|${wants.join(',')}|${depth}`;
    const hit = repo.fetchCache.get(key);
    if (hit && hit.gen === repo.gen) return hit.body;
    const body = buildFetchResponseV0(repo, wants, haves, depth, oldShallow);
    repo.fetchCache.set(key, { gen: repo.gen, body });
    return body;
  }
  return buildFetchResponseV0(repo, wants, haves, depth, oldShallow);
}
function buildFetchResponseV0(repo: Repo, wants: readonly string[], haves: readonly string[], depth: number | null, oldShallow: readonly string[]): Buffer {
  const plan = planFetch(repo, wants, haves, depth, oldShallow);
  const lines: string[] = [];
  if (plan.covered && depth === null) {
    for (const want of wants) lines.push(`ACK ${want}\n`);
    return pktLines([...lines, 'flush']);
  }
  lines.push('NAK\n');
  for (const oid of plan.shallow) lines.push(`shallow ${oid}\n`);
  for (const oid of plan.unshallow) lines.push(`unshallow ${oid}\n`);
  const parts: Buffer[] = [pktLines(lines)];
  if (plan.objects.length > 0 || depth !== null) {
    parts.push(sidebandWrap(buildPack(plan.objects)));
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

/** Handle POST /{owner}/{repo}.git/git-receive-pack. */
function handleReceivePack(repo: Repo, body: Buffer): { status: number; contentType: string; body: Buffer } {
  const report = (unpack: string, refs: Array<{ ref: string; ok: boolean; reason: string }>, sideband: boolean): Buffer => {
    const lines: string[] = [`unpack ${unpack}\n`];
    for (const r of refs) lines.push(r.ok ? `ok ${r.ref}\n` : `ng ${r.ref} ${r.reason}\n`);
    const framed = pktLines([...lines, 'flush']);
    if (!sideband) return framed;
    return Buffer.concat([sidebandWrap(framed), pktFlush()]);
  };
  // Parse command pkt-lines until the first flush; the rest is the pack.
  let off = 0;
  const commands: PushCommand[] = [];
  let firstCaps = '';
  let sideband = false;
  try {
    for (;;) {
      if (off + 4 > body.length) throw new Error('truncated command list');
      const head = body.subarray(off, off + 4).toString('ascii');
      if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error('bad pkt-line length');
      const len = parseInt(head, 16);
      if (len === 0) {
        off += 4;
        break;
      }
      if (len < 4 || off + len > body.length) throw new Error('bad pkt-line length');
      const line = body.subarray(off + 4, off + len).toString('utf8');
      off += len;
      const nul = line.indexOf('\0');
      const text = (nul >= 0 ? line.slice(0, nul) : line).replace(/\n$/, '');
      if (nul >= 0 && firstCaps === '') firstCaps = line.slice(nul + 1).replace(/\n$/, '');
      const parts = text.split(' ');
      if (parts.length !== 3 || !isOid(parts[0]!) || !isOid(parts[1]!)) throw new Error('bad push command');
      commands.push({ oldOid: parts[0]!, newOid: parts[1]!, ref: parts[2]! });
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { status: 400, contentType: 'text/plain; charset=utf-8', body: Buffer.from(`bad request: ${msg}\n`, 'utf8') };
  }
  sideband = firstCaps.split(' ').includes('side-band-64k');
  const packBytes = body.subarray(off);
  if (packBytes.length > 0) {
    try {
      const parsed = parsePack(packBytes, (oid) => repo.objects.get(oid));
      for (const [oid, obj] of parsed.objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      return { status: 200, contentType: 'application/x-git-receive-pack-result', body: report(detail, [], sideband) };
    }
  }
  const results: Array<{ ref: string; ok: boolean; reason: string }> = [];
  for (const cmd of commands) {
    const current = repo.refs.get(cmd.ref);
    if (!cmd.ref.startsWith('refs/')) {
      results.push({ ref: cmd.ref, ok: false, reason: 'invalid ref' });
      continue;
    }
    if (cmd.newOid === ZERO_OID) {
      // delete
      if (!current) {
        results.push({ ref: cmd.ref, ok: false, reason: 'ref does not exist' });
      } else if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== current) {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      } else {
        repo.refs.delete(cmd.ref);
        results.push({ ref: cmd.ref, ok: true, reason: '' });
      }
      continue;
    }
    if (!repo.objects.has(cmd.newOid)) {
      results.push({ ref: cmd.ref, ok: false, reason: 'object not found' });
      continue;
    }
    if (cmd.oldOid === ZERO_OID) {
      if (current) {
        results.push({ ref: cmd.ref, ok: false, reason: 'already exists' });
      } else {
        repo.refs.set(cmd.ref, cmd.newOid);
        results.push({ ref: cmd.ref, ok: true, reason: '' });
      }
      continue;
    }
    if (current !== cmd.oldOid) {
      results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    if (!isAncestor(repo, cmd.oldOid, cmd.newOid)) {
      results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    repo.refs.set(cmd.ref, cmd.newOid);
    results.push({ ref: cmd.ref, ok: true, reason: '' });
  }
  repo.updatedAt = tickIso();
  repo.gen += 1;
  return { status: 200, contentType: 'application/x-git-receive-pack-result', body: report('ok', results, sideband) };
}

/** Handle POST /{owner}/{repo}.git/git-upload-pack (v2 when Git-Protocol says so, else v0). */
function handleUploadPack(repo: Repo, body: Buffer, isV2: boolean): { status: number; contentType: string; body: Buffer } {
  let packets: Pkt[];
  try {
    packets = decodePktLines(body).packets;
  } catch {
    return { status: 400, contentType: 'text/plain; charset=utf-8', body: Buffer.from('bad request: malformed pkt-line\n', 'utf8') };
  }
  const lines = packets.filter((p) => p.kind === 'data').map((p) => p.payload.toString('utf8'));
  if (isV2) {
    const command = (lines[0] ?? '').replace(/\n$/, '');
    if (command === 'command=ls-refs') {
      const args: LsRefsArgs = { peel: false, symrefs: false, unborn: false, prefixes: [] };
      for (const raw of lines.slice(1)) {
        const line = raw.replace(/\n$/, '');
        if (line === 'peel') args.peel = true;
        else if (line === 'symrefs') args.symrefs = true;
        else if (line === 'unborn') args.unborn = true;
        else if (line.startsWith('ref-prefix ')) args.prefixes.push(line.slice('ref-prefix '.length));
      }
      return { status: 200, contentType: 'application/x-git-upload-pack-result', body: lsRefsV2(repo, args) };
    }
    if (command === 'command=fetch') {
      const wants: string[] = [];
      const haves: string[] = [];
      const shallow: string[] = [];
      let depth: number | null = null;
      let deepenRelative = false;
      let done = false;
      for (const raw of lines.slice(1)) {
        const line = raw.replace(/\n$/, '');
        if (line.startsWith('want ')) wants.push(line.slice(5).trim());
        else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
        else if (line.startsWith('shallow ')) shallow.push(line.slice(8).trim());
        else if (line === 'done') done = true;
        else if (line === 'deepen-relative') deepenRelative = true;
        else if (line.startsWith('deepen ')) {
          const n = Number(line.slice(7).trim());
          if (Number.isFinite(n) && n > 0) depth = Math.trunc(n);
        }
      }
      return { status: 200, contentType: 'application/x-git-upload-pack-result', body: fetchResponseV2(repo, wants, haves, depth, shallow, done, deepenRelative) };
    }
    return { status: 400, contentType: 'text/plain; charset=utf-8', body: Buffer.from('bad request: unknown v2 command\n', 'utf8') };
  }
  // v0: wants section, flush, then haves + done, flush.
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | null = null;
  let section = 0;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      section += 1;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (section === 0) {
      if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0]!);
      else if (line.startsWith('shallow ')) shallow.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) {
        const n = Number(line.slice(7).trim());
        if (Number.isFinite(n) && n > 0) depth = Math.trunc(n);
      }
    } else if (line.startsWith('have ')) {
      haves.push(line.slice(5).trim());
    }
  }
  return { status: 200, contentType: 'application/x-git-upload-pack-result', body: fetchResponseV0(repo, wants, haves, depth, shallow) };
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------

interface RestResp {
  status: number;
  body: string;
  headers?: Record<string, string>;
}
function restJson(status: number, value: unknown, headers?: Record<string, string>): RestResp {
  return { status, body: JSON.stringify(value), headers };
}
function restErr(status: number, message: string): RestResp {
  return restJson(status, { message });
}
function viewerUserJson(origin: string): Record<string, unknown> {
  return {
    login: VIEWER_LOGIN,
    id: VIEWER_ID,
    node_id: globalId('U', String(VIEWER_ID)),
    avatar_url: `${origin}/avatars/${VIEWER_LOGIN}.png`,
    gravatar_id: '',
    url: `${origin}/api/v3/users/${VIEWER_LOGIN}`,
    html_url: `${origin}/${VIEWER_LOGIN}`,
    type: 'User',
    site_admin: false,
    name: VIEWER_NAME,
    email: VIEWER_EMAIL,
    public_repos: store.viewerRepos().length,
    followers: 0,
    following: 0,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
  };
}
function repoJson(repo: Repo, origin: string): Record<string, unknown> {
  const base = `${origin}/api/v3/repos/${repo.owner}/${repo.name}`;
  const openIssues = repo.issues.filter((i) => i.state === 'open').length + repo.pulls.filter((p) => p.state === 'open').length;
  return {
    id: repo.id,
    node_id: globalId('R', String(repo.id)),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: repo.owner === VIEWER_LOGIN ? VIEWER_ID : 0, node_id: globalId('U', String(repo.owner === VIEWER_LOGIN ? VIEWER_ID : 0)), type: 'User', site_admin: false, avatar_url: `${origin}/avatars/${repo.owner}.png`, url: `${origin}/api/v3/users/${repo.owner}`, html_url: `${origin}/${repo.owner}` },
    private: repo.isPrivate,
    html_url: `${origin}/${repo.owner}/${repo.name}`,
    description: repo.description,
    fork: false,
    url: base,
    archive_url: `${base}/{archive_format}{/ref}`,
    assignees_url: `${base}/assignees{/user}`,
    blobs_url: `${base}/git/blobs{/sha}`,
    branches_url: `${base}/branches{/branch}`,
    clone_url: `${origin}/${repo.owner}/${repo.name}.git`,
    collaborators_url: `${base}/collaborators{/collaborator}`,
    comments_url: `${base}/comments{/number}`,
    commits_url: `${base}/commits{/sha}`,
    compare_url: `${base}/compare/{base}...{head}`,
    contents_url: `${base}/contents/{+path}`,
    contributors_url: `${base}/contributors`,
    deployments_url: `${base}/deployments`,
    downloads_url: `${base}/downloads`,
    events_url: `${base}/events`,
    forks_url: `${base}/forks`,
    git_commits_url: `${base}/git/commits{/sha}`,
    git_refs_url: `${base}/git/refs{/ref}`,
    git_tags_url: `${base}/git/tags{/sha}`,
    git_url: `git://keystone/${repo.owner}/${repo.name}.git`,
    issue_comment_url: `${base}/issues/comments{/number}`,
    issue_events_url: `${base}/issues/events{/number}`,
    issues_url: `${base}/issues{/number}`,
    keys_url: `${base}/keys{/key_id}`,
    labels_url: `${base}/labels{/name}`,
    languages_url: `${base}/languages`,
    merges_url: `${base}/merges`,
    milestones_url: `${base}/milestones{/number}`,
    notifications_url: `${base}/notifications{?since,all,participating}`,
    pulls_url: `${base}/pulls{/number}`,
    releases_url: `${base}/releases{/id}`,
    ssh_url: `git@keystone:${repo.owner}/${repo.name}.git`,
    stargazers_url: `${base}/stargazers`,
    statuses_url: `${base}/statuses/{sha}`,
    subscribers_url: `${base}/subscribers`,
    subscription_url: `${base}/subscription`,
    tags_url: `${base}/tags`,
    teams_url: `${base}/teams`,
    trees_url: `${base}/git/trees{/sha}`,
    homepage: null,
    language: null,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    size: 0,
    default_branch: repo.defaultBranch,
    open_issues_count: openIssues,
    is_template: false,
    topics: [],
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: false,
    has_pages: false,
    has_discussions: false,
    archived: false,
    disabled: false,
    visibility: repo.isPrivate ? 'private' : 'public',
    pushed_at: repo.updatedAt,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
    allow_rebase_merge: true,
    allow_squash_merge: true,
    allow_merge_commit: true,
    license: null,
  };
}
function commitJson(repo: Repo, sha: string, data: Buffer, origin: string): Record<string, unknown> {
  const view = parseCommit(data);
  const ts = commitTimestamp(data);
  const date = new Date(ts * 1000).toISOString();
  const base = `${origin}/api/v3/repos/${repo.owner}/${repo.name}`;
  return {
    sha,
    node_id: globalId('C', sha),
    url: `${base}/commits/${sha}`,
    html_url: `${origin}/${repo.owner}/${repo.name}/commit/${sha}`,
    author: { login: VIEWER_LOGIN, id: VIEWER_ID, node_id: globalId('U', String(VIEWER_ID)), type: 'User' },
    committer: { login: VIEWER_LOGIN, id: VIEWER_ID, node_id: globalId('U', String(VIEWER_ID)), type: 'User' },
    commit: {
      message: view.message,
      url: `${base}/git/commits/${sha}`,
      author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date },
      committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date },
      tree: { sha: view.tree, url: `${base}/git/trees/${view.tree}` },
      comment_count: 0,
    },
    parents: view.parents.map((p) => ({ sha: p, url: `${base}/commits/${p}`, html_url: `${origin}/${repo.owner}/${repo.name}/commit/${p}` })),
  };
}
function labelJson(repo: Repo, label: Label, origin: string): Record<string, unknown> {
  return {
    id: label.id,
    node_id: globalId('L', `${repo.id}:${label.name}`),
    url: `${origin}/api/v3/repos/${repo.owner}/${repo.name}/labels/${encodeURIComponent(label.name)}`,
    name: label.name,
    color: label.color,
    default: false,
    description: label.description,
  };
}
function issueJson(repo: Repo, issue: Issue, origin: string): Record<string, unknown> {
  const base = `${origin}/api/v3/repos/${repo.owner}/${repo.name}`;
  return {
    id: issue.id,
    node_id: globalId('I', `${repo.id}:${issue.number}`),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    locked: false,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, node_id: globalId('U', String(VIEWER_ID)), type: 'User' },
    labels: issue.labels.map((name) => {
      const label = repo.labels.find((l) => l.name === name);
      return label ? labelJson(repo, label, origin) : { id: 0, node_id: globalId('L', `${repo.id}:${name}`), url: `${base}/labels/${encodeURIComponent(name)}`, name, color: 'ededed', default: false, description: '' };
    }),
    assignee: null,
    assignees: [],
    milestone: null,
    comments: issue.comments.length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    author_association: 'OWNER',
    state_reason: null,
    url: `${base}/issues/${issue.number}`,
    repository_url: base,
    labels_url: `${base}/issues/${issue.number}/labels{/name}`,
    comments_url: `${base}/issues/${issue.number}/comments`,
    events_url: `${base}/issues/${issue.number}/events`,
    html_url: `${origin}/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}
function cachedIssueJson(repo: Repo, issue: Issue, origin: string): string {
  const hit = repo.issueJson.get(issue.number);
  if (hit !== undefined) return hit;
  const text = JSON.stringify(issueJson(repo, issue, origin));
  repo.issueJson.set(issue.number, text);
  return text;
}
function commentJson(repo: Repo, issue: Issue, comment: Comment, origin: string): Record<string, unknown> {
  const base = `${origin}/api/v3/repos/${repo.owner}/${repo.name}`;
  return {
    id: comment.id,
    node_id: globalId('IC', `${repo.id}:${issue.number}:${comment.id}`),
    url: `${base}/issues/comments/${comment.id}`,
    html_url: `${origin}/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
    body: comment.body,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, node_id: globalId('U', String(VIEWER_ID)), type: 'User' },
    created_at: comment.createdAt,
    updated_at: comment.updatedAt,
    issue_url: `${base}/issues/${issue.number}`,
    author_association: 'OWNER',
  };
}
function pullJson(repo: Repo, pull: Pull, origin: string): Record<string, unknown> {
  const base = `${origin}/api/v3/repos/${repo.owner}/${repo.name}`;
  return {
    id: pull.id,
    node_id: globalId('P', `${repo.id}:${pull.number}`),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    locked: false,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, node_id: globalId('U', String(VIEWER_ID)), type: 'User' },
    labels: [],
    milestone: null,
    active_lock_reason: null,
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    closed_at: pull.closedAt,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeSha,
    merged: pull.merged,
    mergeable: pullConflicts(repo, pull) ? false : true,
    mergeable_state: pullConflicts(repo, pull) ? 'dirty' : 'clean',
    merged_by: pull.merged ? { login: VIEWER_LOGIN, id: VIEWER_ID, node_id: globalId('U', String(VIEWER_ID)), type: 'User' } : null,
    comments: 0,
    review_comments: 0,
    commits: listCommits(repo, pull.headSha, 100).length,
    additions: pullFiles(repo, pull).reduce((n, f) => n + f.additions, 0),
    deletions: pullFiles(repo, pull).reduce((n, f) => n + f.deletions, 0),
    changed_files: pullFiles(repo, pull).length,
    head: { label: `${repo.owner}:${pull.head}`, ref: pull.head, sha: pull.headSha, user: { login: VIEWER_LOGIN, id: VIEWER_ID }, repo: repoJson(repo, origin) },
    base: { label: `${repo.owner}:${pull.base}`, ref: pull.base, sha: pull.baseSha, user: { login: VIEWER_LOGIN, id: VIEWER_ID }, repo: repoJson(repo, origin) },
    url: `${base}/pulls/${pull.number}`,
    html_url: `${origin}/${repo.owner}/${repo.name}/pull/${pull.number}`,
    diff_url: `${origin}/${repo.owner}/${repo.name}/pull/${pull.number}.diff`,
    patch_url: `${origin}/${repo.owner}/${repo.name}/pull/${pull.number}.patch`,
    issue_url: `${base}/issues/${pull.number}`,
    statuses_url: `${base}/commits/${pull.headSha}/status`,
    author_association: 'OWNER',
    draft: false,
  };
}

/** Page a list: returns the page slice and a Link header value when more pages exist. */
function paginate<T>(items: readonly T[], query: URLSearchParams, origin: string, pathname: string): { page: T[]; link: string | undefined } {
  const perPageRaw = Number(query.get('per_page') ?? '30');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(Math.trunc(perPageRaw), 100) : 30;
  const pageRaw = Number(query.get('page') ?? '1');
  const pageNum = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.trunc(pageRaw) : 1;
  const start = (pageNum - 1) * perPage;
  const page = items.slice(start, start + perPage);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  if (pageNum >= totalPages) return { page, link: undefined };
  const next = `${origin}${pathname}?per_page=${perPage}&page=${pageNum + 1}`;
  const last = `${origin}${pathname}?per_page=${perPage}&page=${totalPages}`;
  return { page, link: `<${next}>; rel="next", <${last}>; rel="last"` };
}

let seqCounter = 0;
function nextSeq(): number {
  seqCounter += 1;
  return seqCounter;
}

/** The tree oid of a directory inside a tree, or null when absent. */
function dirTreeOid(repo: Repo, treeOid: string, dirPath: string): string | null {
  if (dirPath === '') return treeOid;
  let current = treeOid;
  for (const seg of dirPath.split('/')) {
    const obj = repo.objects.get(current);
    if (!obj || obj.type !== 'tree') return null;
    const entry = parseTree(obj.data).find((e) => e.name === seg && e.mode === '40000');
    if (!entry) return null;
    current = entry.oid;
  }
  return current;
}

function handleRest(method: string, segments: string[], query: URLSearchParams, body: unknown, origin: string, pathname: string): RestResp {
  // segments[0] === 'api', segments[1] === 'v3'
  if (segments.length === 2) {
    if (method === 'GET') return restJson(200, {}, { 'X-OAuth-Scopes': 'repo, user' });
    return restErr(404, 'Not Found');
  }
  const tail = segments.slice(2);
  if (tail[0] === 'meta' && method === 'GET') {
    return restJson(200, { installed_version: FORGE_VERSION, github_enterprise: false, verifiable_password_authentication: true });
  }
  if (tail[0] === 'user' && tail.length === 1) {
    if (method === 'GET') return restJson(200, viewerUserJson(origin));
    return restErr(404, 'Not Found');
  }
  if (tail[0] === 'user' && tail[1] === 'repos') {
    if (method === 'GET') {
      const { page, link } = paginate(store.viewerRepos(), query, origin, pathname);
      return restJson(200, page.map((r) => repoJson(r, origin)), link ? { Link: link } : undefined);
    }
    if (method === 'POST') {
      const input = (body ?? {}) as Record<string, unknown>;
      const name = String(input.name ?? '').trim();
      if (!name || !/^[A-Za-z0-9._-]+$/.test(name)) return restErr(422, 'name is invalid');
      if (store.getRepo(VIEWER_LOGIN, name)) return restErr(422, `Repository ${VIEWER_LOGIN}/${name} already exists`);
      const repo = store.createRepo(VIEWER_LOGIN, name, typeof input.description === 'string' ? input.description : '', input.private === true);
      return restJson(201, repoJson(repo, origin));
    }
    return restErr(404, 'Not Found');
  }
  if (tail[0] !== 'repos' || tail.length < 3) return restErr(404, 'Not Found');
  const owner = tail[1]!;
  const repoName = tail[2]!;
  const repo = store.getRepo(owner, repoName);
  if (!repo) return restErr(404, 'Not Found');
  const rest = tail.slice(3);
  const base = `${origin}/api/v3/repos/${owner}/${repoName}`;

  if (rest.length === 0) {
    if (method === 'GET') return restJson(200, repoJson(repo, origin));
    if (method === 'PATCH') {
      const input = (body ?? {}) as Record<string, unknown>;
      if (typeof input.description === 'string') repo.description = input.description;
      if (typeof input.default_branch === 'string' && input.default_branch) repo.defaultBranch = input.default_branch;
      repo.updatedAt = tickIso();
      return restJson(200, repoJson(repo, origin));
    }
    if (method === 'DELETE') {
      store.deleteRepo(owner, repoName);
      return { status: 204, body: '' };
    }
    return restErr(404, 'Not Found');
  }

  if (rest[0] === 'branches') {
    const branchName = rest.slice(1).join('/');
    const branches = [...repo.refs.keys()].filter((r) => r.startsWith('refs/heads/')).map((r) => r.slice('refs/heads/'.length)).sort();
    const branchJson = (name: string) => {
      const sha = repo.refs.get(`refs/heads/${name}`)!;
      return { name, commit: { sha, url: `${base}/commits/${sha}` }, protected: false };
    };
    if (method === 'GET' && branchName === '') {
      return restJson(200, branches.map(branchJson));
    }
    if (method === 'GET' && branches.includes(branchName)) {
      return restJson(200, branchJson(branchName));
    }
    return restErr(404, 'Not Found');
  }

  if (rest[0] === 'git' && rest[1] === 'refs') {
    const refPath = rest.slice(2).join('/');
    if (method === 'POST' && refPath === '') {
      const input = (body ?? {}) as Record<string, unknown>;
      const ref = String(input.ref ?? '');
      const sha = String(input.sha ?? '');
      if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) return restErr(422, 'ref or sha is invalid');
      if (repo.refs.has(ref)) return restErr(422, 'Reference already exists');
      repo.refs.set(ref, sha);
      repo.gen += 1;
      return restJson(201, { ref, node_id: globalId('G', `${repo.id}:${ref}`), url: `${base}/git/refs/${ref}`, object: { sha, type: repo.objects.get(sha)!.type, url: `${base}/git/${repo.objects.get(sha)!.type}s/${sha}` } });
    }
    if (method === 'GET' && refPath === '') {
      const all = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([ref, sha]) => ({ ref, node_id: globalId('G', `${repo.id}:${ref}`), url: `${base}/git/refs/${ref}`, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit', url: `${base}/git/commits/${sha}` } }));
      return restJson(200, all);
    }
    if (method === 'GET') {
      const ref = refPath.startsWith('refs/') ? refPath : `refs/${refPath}`;
      const sha = repo.refs.get(ref);
      if (!sha) return restErr(404, 'Not Found');
      return restJson(200, { ref, node_id: globalId('G', `${repo.id}:${ref}`), url: `${base}/git/refs/${ref}`, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit', url: `${base}/git/commits/${sha}` } });
    }
    if (method === 'PATCH' || method === 'DELETE') {
      const ref = refPath.startsWith('refs/') ? refPath : `refs/${refPath}`;
      if (!repo.refs.has(ref)) return restErr(404, 'Not Found');
      if (method === 'DELETE') {
        repo.refs.delete(ref);
        repo.gen += 1;
        return { status: 204, body: '' };
      }
      const input = (body ?? {}) as Record<string, unknown>;
      const sha = String(input.sha ?? '');
      if (!isOid(sha) || !repo.objects.has(sha)) return restErr(422, 'sha is invalid');
      repo.refs.set(ref, sha);
      repo.gen += 1;
      return restJson(200, { ref, node_id: globalId('G', `${repo.id}:${ref}`), url: `${base}/git/refs/${ref}`, object: { sha, type: repo.objects.get(sha)!.type, url: `${base}/git/commits/${sha}` } });
    }
    return restErr(404, 'Not Found');
  }

  if (rest[0] === 'commits') {
    if (method === 'GET' && rest.length === 1) {
      const shaParam = query.get('sha') ?? repo.defaultBranch;
      const tip = repo.refs.get(`refs/heads/${shaParam}`) ?? (isOid(shaParam) ? shaParam : undefined);
      const list = listCommits(repo, tip);
      const { page, link } = paginate(list, query, origin, pathname);
      return restJson(200, page.map((c) => commitJson(repo, c.sha, c.data, origin)), link ? { Link: link } : undefined);
    }
    if (method === 'GET' && rest.length === 2) {
      const obj = repo.objects.get(rest[1]!);
      if (!obj || obj.type !== 'commit') return restErr(404, 'Not Found');
      return restJson(200, commitJson(repo, rest[1]!, obj.data, origin));
    }
    return restErr(404, 'Not Found');
  }

  if (rest[0] === 'contents') {
    const path = rest.slice(1).join('/');
    const bodyObj = (body ?? {}) as Record<string, unknown>;
    const branch = query.get('ref') ?? (typeof bodyObj.branch === 'string' && bodyObj.branch ? bodyObj.branch : repo.defaultBranch);
    const tip = repo.refs.get(`refs/heads/${branch}`);
    if (method === 'GET') {
      const files = fileMapOf(repo, tip);
      if (files.has(path)) {
        const oid = files.get(path)!;
        const blob = repo.objects.get(oid)!;
        return restJson(200, {
          type: 'file', encoding: 'base64', size: blob.data.length, name: path.split('/').pop()!, path, content: blob.data.toString('base64'), sha: oid,
          url: `${base}/contents/${path}`, git_url: `${base}/git/blobs/${oid}`, html_url: `${origin}/${owner}/${repoName}/blob/${branch}/${path}`, download_url: `${origin}/${owner}/${repoName}/raw/${branch}/${path}`,
        });
      }
      // directory listing (path '' is the root)
      const prefix = path === '' ? '' : `${path}/`;
      const children = new Map<string, { type: 'file' | 'dir'; name: string; path: string; sha: string }>();
      for (const [filePath, oid] of files) {
        if (!filePath.startsWith(prefix)) continue;
        const restPath = filePath.slice(prefix.length);
        const slash = restPath.indexOf('/');
        if (slash < 0) {
          children.set(restPath, { type: 'file', name: restPath, path: filePath, sha: oid });
        } else {
          const dirName = restPath.slice(0, slash);
          if (!children.has(dirName)) {
            const dirPath = prefix + dirName;
            const treeOid = tip ? dirTreeOid(repo, parseCommit(repo.objects.get(tip)!.data).tree, dirPath) : null;
            children.set(dirName, { type: 'dir', name: dirName, path: dirPath, sha: treeOid ?? '' });
          }
        }
      }
      if (children.size === 0) return restErr(404, 'Not Found');
      const entries = [...children.values()].sort((a, b) => (a.name < b.name ? -1 : 1)).map((e) => ({
        type: e.type, name: e.name, path: e.path, sha: e.sha, size: e.type === 'file' ? repo.objects.get(e.sha)?.data.length ?? 0 : 0,
        url: `${base}/contents/${e.path}`, git_url: `${base}/git/${e.type === 'file' ? 'blobs' : 'trees'}/${e.sha}`, html_url: `${origin}/${owner}/${repoName}/${e.type === 'file' ? 'blob' : 'tree'}/${branch}/${e.path}`, download_url: e.type === 'file' ? `${origin}/${owner}/${repoName}/raw/${branch}/${e.path}` : null,
      }));
      return restJson(200, entries);
    }
    if (method === 'PUT') {
      const input = (body ?? {}) as Record<string, unknown>;
      const message = typeof input.message === 'string' ? input.message : 'Update file';
      const contentB64 = typeof input.content === 'string' ? input.content : '';
      const targetBranch = typeof input.branch === 'string' && input.branch ? input.branch : repo.defaultBranch;
      const files = fileMapOf(repo, repo.refs.get(`refs/heads/${targetBranch}`));
      const exists = files.has(path);
      if (exists && typeof input.sha !== 'string') return restErr(422, 'sha is required to update a file');
      if (exists && input.sha !== files.get(path)) return restErr(409, 'sha does not match the current file');
      const content = b64decode(contentB64);
      const { commitSha, blobSha } = commitContentChange(repo, targetBranch, path, content, message);
      const commitDate = tickIso();
      const status = exists ? 200 : 201;
      return restJson(status, {
        content: { name: path.split('/').pop()!, path, sha: blobSha, size: content.length, type: 'file', encoding: 'base64', content: contentB64, url: `${base}/contents/${path}`, git_url: `${base}/git/blobs/${blobSha}`, html_url: `${origin}/${owner}/${repoName}/blob/${targetBranch}/${path}`, download_url: `${origin}/${owner}/${repoName}/raw/${targetBranch}/${path}` },
        commit: { sha: commitSha, message, url: `${base}/commits/${commitSha}`, html_url: `${origin}/${owner}/${repoName}/commit/${commitSha}`, author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: commitDate }, committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: commitDate } },
      });
    }
    if (method === 'DELETE') {
      const input = (body ?? {}) as Record<string, unknown>;
      const message = typeof input.message === 'string' ? input.message : 'Delete file';
      const targetBranch = typeof input.branch === 'string' && input.branch ? input.branch : repo.defaultBranch;
      const files = fileMapOf(repo, repo.refs.get(`refs/heads/${targetBranch}`));
      if (!files.has(path)) return restErr(404, 'Not Found');
      if (typeof input.sha === 'string' && input.sha !== files.get(path)) return restErr(409, 'sha does not match the current file');
      const { commitSha } = commitContentChange(repo, targetBranch, path, null, message);
      return restJson(200, { commit: { sha: commitSha, message, url: `${base}/commits/${commitSha}`, html_url: `${origin}/${owner}/${repoName}/commit/${commitSha}` } });
    }
    return restErr(404, 'Not Found');
  }

  if (rest[0] === 'labels') {
    if (method === 'GET' && rest.length === 1) {
      return restJson(200, repo.labels.map((l) => labelJson(repo, l, origin)));
    }
    if (method === 'POST' && rest.length === 1) {
      const input = (body ?? {}) as Record<string, unknown>;
      const name = String(input.name ?? '').trim();
      if (!name) return restErr(422, 'name is required');
      if (repo.labels.some((l) => l.name === name)) return restErr(422, 'Label already exists');
      const label: Label = {
        id: allocId(),
        name,
        color: typeof input.color === 'string' && /^[0-9a-fA-F]{6}$/.test(input.color) ? input.color.toLowerCase() : 'ededed',
        description: typeof input.description === 'string' ? input.description : '',
      };
      repo.labels.push(label);
      return restJson(201, labelJson(repo, label, origin));
    }
    if (method === 'GET' && rest.length === 2) {
      const label = repo.labels.find((l) => l.name === decodeURIComponent(rest[1]!));
      if (!label) return restErr(404, 'Not Found');
      return restJson(200, labelJson(repo, label, origin));
    }
    return restErr(404, 'Not Found');
  }

  if (rest[0] === 'issues') {
    const num = rest[1] ? Number(rest[1]) : NaN;
    if (rest.length === 1 && method === 'POST') {
      const input = (body ?? {}) as Record<string, unknown>;
      const title = typeof input.title === 'string' ? input.title : '';
      if (!title) return restErr(422, 'title is required');
      const labelNames: string[] = Array.isArray(input.labels) ? input.labels.map((l) => String(l)) : [];
      for (const name of labelNames) {
        if (!repo.labels.some((l) => l.name === name)) return restErr(422, `Label does not exist: ${name}`);
      }
      const now = tickIso();
      const issue: Issue = {
        id: allocId(),
        number: repo.nextNumber++,
        title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        labels: labelNames,
        comments: [],
        createdAt: now,
        updatedAt: now,
        closedAt: null,
        seq: nextSeq(),
      };
      repo.issues.push(issue);
      return restJson(201, issueJson(repo, issue, origin));
    }
    if (rest.length === 1 && method === 'GET') {
      const state = query.get('state') ?? 'open';
      const direction = query.get('direction') ?? 'desc';
      let list = repo.issues.filter((i) => (state === 'all' ? true : i.state === state));
      list = [...list].sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
      const { page, link } = paginate(list, query, origin, pathname);
      return restJson(200, page.map((i) => JSON.parse(cachedIssueJson(repo, i, origin))), link ? { Link: link } : undefined);
    }
    const issue = Number.isFinite(num) ? repo.issues.find((i) => i.number === num) : undefined;
    if (!issue) return restErr(404, 'Not Found');
    if (rest.length === 2 && method === 'GET') {
      return { status: 200, body: cachedIssueJson(repo, issue, origin) };
    }
    if (rest.length === 2 && method === 'PATCH') {
      const input = (body ?? {}) as Record<string, unknown>;
      if (typeof input.title === 'string') issue.title = input.title;
      if (typeof input.body === 'string') issue.body = input.body;
      if (input.state === 'open' || input.state === 'closed') {
        issue.state = input.state;
        issue.closedAt = input.state === 'closed' ? tickIso() : null;
      }
      issue.updatedAt = tickIso();
      repo.issueJson.delete(issue.number);
      return restJson(200, issueJson(repo, issue, origin));
    }
    if (rest[2] === 'comments' && method === 'POST') {
      const input = (body ?? {}) as Record<string, unknown>;
      const text = typeof input.body === 'string' ? input.body : '';
      if (!text) return restErr(422, 'body is required');
      const now = tickIso();
      const comment: Comment = { id: allocId(), body: text, createdAt: now, updatedAt: now };
      issue.comments.push(comment);
      issue.updatedAt = now;
      repo.issueJson.delete(issue.number);
      return restJson(201, commentJson(repo, issue, comment, origin));
    }
    if (rest[2] === 'comments' && method === 'GET') {
      return restJson(200, issue.comments.map((c) => commentJson(repo, issue, c, origin)));
    }
    return restErr(404, 'Not Found');
  }

  if (rest[0] === 'pulls') {
    const num = rest[1] ? Number(rest[1]) : NaN;
    if (rest.length === 1 && method === 'POST') {
      const input = (body ?? {}) as Record<string, unknown>;
      const head = typeof input.head === 'string' ? input.head : '';
      const baseName = typeof input.base === 'string' ? input.base : repo.defaultBranch;
      const title = typeof input.title === 'string' ? input.title : '';
      if (!head || !title) return restErr(422, 'head and title are required');
      const headSha = repo.refs.get(`refs/heads/${head}`);
      const baseSha = repo.refs.get(`refs/heads/${baseName}`);
      if (!headSha || !baseSha) return restErr(422, 'head or base branch does not exist');
      if (repo.pulls.some((p) => p.state === 'open' && p.head === head && p.base === baseName)) {
        return restErr(422, 'A pull request already exists for this head and base');
      }
      const now = tickIso();
      const pull: Pull = {
        id: allocId(),
        number: repo.nextNumber++,
        title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        head,
        base: baseName,
        headSha,
        baseSha,
        merged: false,
        mergedAt: null,
        mergeSha: null,
        createdAt: now,
        updatedAt: now,
        closedAt: null,
        seq: nextSeq(),
      };
      repo.pulls.push(pull);
      return restJson(201, pullJson(repo, pull, origin));
    }
    if (rest.length === 1 && method === 'GET') {
      const state = query.get('state') ?? 'open';
      const list = [...repo.pulls.filter((p) => (state === 'all' ? true : p.state === state))].sort((a, b) => b.seq - a.seq);
      const { page, link } = paginate(list, query, origin, pathname);
      return restJson(200, page.map((p) => pullJson(repo, p, origin)), link ? { Link: link } : undefined);
    }
    const pull = Number.isFinite(num) ? repo.pulls.find((p) => p.number === num) : undefined;
    if (!pull) return restErr(404, 'Not Found');
    if (rest.length === 2 && method === 'GET') {
      return restJson(200, pullJson(repo, pull, origin));
    }
    if (rest[2] === 'files' && method === 'GET') {
      return restJson(200, pullFiles(repo, pull).map((f) => ({
        sha: '',
        filename: f.filename,
        status: f.status,
        additions: f.additions,
        deletions: f.deletions,
        changes: f.changes,
        blob_url: `${base}/blob/${pull.headSha}/${f.filename}`,
        raw_url: `${origin}/${owner}/${repoName}/raw/${pull.headSha}/${f.filename}`,
        contents_url: `${base}/contents/${f.filename}?ref=${pull.head}`,
        patch: '',
      })));
    }
    if (rest[2] === 'merge' && method === 'PUT') {
      if (pull.state === 'closed') return restErr(405, 'Pull Request is already merged or closed');
      if (pullConflicts(repo, pull)) return restErr(405, 'Merge conflict');
      const mergeSha = squashMerge(repo, pull);
      const now = tickIso();
      pull.state = 'closed';
      pull.merged = true;
      pull.mergedAt = now;
      pull.mergeSha = mergeSha;
      pull.closedAt = now;
      pull.updatedAt = now;
      return restJson(200, { merged: true, sha: mergeSha, message: `Merge pull request #${pull.number} from ${owner}/${pull.head}` });
    }
    return restErr(404, 'Not Found');
  }

  return restErr(404, 'Not Found');
}

// ---------------------------------------------------------------------------
// GraphQL v4: hand-rolled parser + executor (no dependency)
// ---------------------------------------------------------------------------

type GqlValue =
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'variable'; name: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GqlValue }> };
interface GqlField {
  kind: 'field';
  name: string;
  alias: string;
  args: Array<{ name: string; value: GqlValue }>;
  selection: GqlSelection[] | null;
}
interface GqlInlineFragment {
  kind: 'inline';
  typeCondition: string | null;
  selection: GqlSelection[];
}
interface GqlSpread {
  kind: 'spread';
  name: string;
}
type GqlSelection = GqlField | GqlInlineFragment | GqlSpread;
interface GqlOperation {
  type: 'query' | 'mutation';
  name: string | null;
  selection: GqlSelection[];
}
interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, GqlSelection[]>;
}

function gqlTokenize(query: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < query.length) {
    const ch = query[i]!;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < query.length && query[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < query.length && query[j] !== '"') {
        if (query[j] === '\\' && j + 1 < query.length) {
          const esc = query[j + 1]!;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += query[j];
          j += 1;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if ('{}()[]:!=@'.includes(ch)) {
      if (ch === '.' && query.slice(i, i + 3) === '...') {
        tokens.push('...');
        i += 3;
        continue;
      }
      tokens.push(ch);
      i += 1;
      continue;
    }
    if (ch === '$') {
      let j = i + 1;
      while (j < query.length && /[A-Za-z0-9_]/.test(query[j]!)) j += 1;
      tokens.push(query.slice(i, j));
      i = j;
      continue;
    }
    let j = i;
    while (j < query.length && /[A-Za-z0-9_.-]/.test(query[j]!) && !'{}()[]:!=$@,'.includes(query[j]!)) j += 1;
    if (j === i) throw new Error(`unexpected character ${JSON.stringify(ch)} in GraphQL document`);
    tokens.push(query.slice(i, j));
    i = j;
  }
  return tokens;
}

class GqlParser {
  tokens: string[];
  pos = 0;
  constructor(query: string) {
    this.tokens = gqlTokenize(query);
  }
  peek(): string | undefined {
    return this.tokens[this.pos];
  }
  next(): string {
    const t = this.tokens[this.pos];
    this.pos += 1;
    return t ?? '';
  }
  expect(token: string): void {
    const got = this.next();
    if (got !== token) throw new Error(`expected ${token} in GraphQL document, got ${JSON.stringify(got)}`);
  }
  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, GqlSelection[]>();
    while (this.pos < this.tokens.length) {
      const head = this.peek();
      if (head === 'query' || head === 'mutation') {
        this.next();
        let name: string | null = null;
        if (this.peek() && this.peek() !== '(' && this.peek() !== '{') name = this.next();
        if (this.peek() === '(') this.skipParens();
        const selection = this.parseSelectionSet();
        operations.push({ type: head as 'query' | 'mutation', name, selection });
      } else if (head === 'fragment') {
        this.next();
        const name = this.next();
        this.expect('on');
        this.next(); // type condition (ignored; spreads are expanded inline)
        const selection = this.parseSelectionSet();
        fragments.set(name, selection);
      } else if (head === '{') {
        operations.push({ type: 'query', name: null, selection: this.parseSelectionSet() });
      } else {
        throw new Error(`unexpected token ${JSON.stringify(head)} in GraphQL document`);
      }
    }
    return { operations, fragments };
  }
  skipParens(): void {
    this.expect('(');
    let depth = 1;
    while (depth > 0) {
      const t = this.next();
      if (t === '(' || t === '[' || t === '{') depth += 1;
      else if (t === ')' || t === ']' || t === '}') depth -= 1;
      if (t === '') throw new Error('unterminated parentheses in GraphQL document');
    }
  }
  parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    const out: GqlSelection[] = [];
    while (this.peek() !== '}' && this.peek() !== undefined) {
      out.push(this.parseSelection());
    }
    this.expect('}');
    return out;
  }
  parseSelection(): GqlSelection {
    if (this.peek() === '...') {
      this.next();
      if (this.peek() === 'on') {
        this.next();
        const typeCondition = this.next();
        return { kind: 'inline', typeCondition, selection: this.parseSelectionSet() };
      }
      return { kind: 'spread', name: this.next() };
    }
    let name = this.next();
    let alias = name;
    if (this.peek() === ':') {
      this.next();
      alias = name;
      name = this.next();
    }
    const args: Array<{ name: string; value: GqlValue }> = [];
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== ')') {
        const argName = this.next();
        this.expect(':');
        args.push({ name: argName, value: this.parseValue() });
      }
      this.expect(')');
    }
    let selection: GqlSelection[] | null = null;
    if (this.peek() === '{') selection = this.parseSelectionSet();
    return { kind: 'field', name, alias, args, selection };
  }
  parseValue(): GqlValue {
    const t = this.next();
    if (t === '') throw new Error('unexpected end of GraphQL document');
    if (t.startsWith('"')) return { kind: 'string', value: JSON.parse(t) as string };
    if (t === '[') {
      const values: GqlValue[] = [];
      while (this.peek() !== ']') values.push(this.parseValue());
      this.expect(']');
      return { kind: 'list', values };
    }
    if (t === '{') {
      const fields: Array<{ name: string; value: GqlValue }> = [];
      while (this.peek() !== '}') {
        const name = this.next();
        this.expect(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.expect('}');
      return { kind: 'object', fields };
    }
    if (t.startsWith('$')) return { kind: 'variable', name: t.slice(1) };
    if (t === 'true') return { kind: 'boolean', value: true };
    if (t === 'false') return { kind: 'boolean', value: false };
    if (t === 'null') return { kind: 'null' };
    if (/^-?\d+$/.test(t)) return { kind: 'int', value: Number(t) };
    if (/^-?\d*\.\d+$/.test(t)) return { kind: 'float', value: Number(t) };
    return { kind: 'enum', value: t };
  }
}

/** Resolve a parsed value against the operation variables. */
function gqlResolveValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
      return value.value;
    case 'null':
      return null;
    case 'enum':
      return value.value;
    case 'variable':
      return variables[value.name];
    case 'list':
      return value.values.map((v) => gqlResolveValue(v, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const f of value.fields) out[f.name] = gqlResolveValue(f.value, variables);
      return out;
    }
  }
}
function gqlArgs(field: GqlField, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const a of field.args) out[a.name] = gqlResolveValue(a.value, variables);
  return out;
}

// --- GraphQL executor ------------------------------------------------------

interface GqlCtx {
  origin: string;
  errors: string[];
  fragments: Map<string, GqlSelection[]>;
}

class GqlError extends Error {}

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'url', 'createdAt', 'updatedAt', 'closedAt', 'author', 'labels', 'comments', 'repository', 'timelineItems', 'participants', 'locked', 'stateReason'],
  PullRequest: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'mergeable', 'merged', 'mergedAt', 'mergeCommit', 'files', 'commits', 'author', 'createdAt', 'updatedAt', 'url', 'repository', 'labels', 'reviewers', 'isDraft'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'description', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'isPrivate', 'isArchived', 'url', 'createdAt', 'updatedAt', 'issue', 'issues', 'pullRequest', 'pullRequests', 'labels', 'stargazerCount', 'forkCount', 'watchers', 'homepageUrl', 'primaryLanguage'],
  Viewer: ['login', 'id', 'name', 'email', 'avatarUrl', 'url', 'repositories', 'issues', 'pullRequests'],
  User: ['login', 'id', 'name', 'email', 'avatarUrl', 'url'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  LabelConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  CommentConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  IssueEdge: ['node', 'cursor'],
  PullRequestEdge: ['node', 'cursor'],
  LabelEdge: ['node', 'cursor'],
  CommentEdge: ['node', 'cursor'],
  PullRequestFileEdge: ['node', 'cursor'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  Label: ['id', 'name', 'color', 'description', 'url'],
  Comment: ['id', 'body', 'author', 'createdAt', 'updatedAt', 'url'],
  Ref: ['name', 'prefix', 'target'],
  Commit: ['oid', 'message', 'author', 'committer', 'tree'],
  PullRequestFile: ['path', 'additions', 'deletions', 'changeType'],
  SearchType: [],
};
const GQL_ENUM_VALUES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE', 'MILESTONE'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
};

function gqlUserObj(login: string, id: number, origin: string): Record<string, unknown> {
  return { __typename: 'User', login, id, name: login === VIEWER_LOGIN ? VIEWER_NAME : login, email: login === VIEWER_LOGIN ? VIEWER_EMAIL : `${login}@example.invalid`, avatarUrl: `${origin}/avatars/${login}.png`, url: `${origin}/${login}` };
}
function gqlRepoObj(repo: Repo): Record<string, unknown> {
  return { __typename: 'Repository', repo };
}
function gqlIssueObj(repo: Repo, issue: Issue): Record<string, unknown> {
  return { __typename: 'Issue', repo, issue };
}
function gqlPullObj(repo: Repo, pull: Pull): Record<string, unknown> {
  return { __typename: 'PullRequest', repo, pull };
}
function gqlCursor(key: string): string {
  return b64encode(`cursor:${key}`);
}
function gqlPageInfo<T>(items: readonly T[], page: readonly T[], key: (item: T) => string): Record<string, unknown> {
  const start = page.length > 0 ? gqlCursor(key(page[0]!)) : null;
  const end = page.length > 0 ? gqlCursor(key(page[page.length - 1]!)) : null;
  const firstIndex = page.length > 0 ? items.indexOf(page[0]!) : -1;
  const lastIndex = page.length > 0 ? items.indexOf(page[page.length - 1]!) : -1;
  return {
    __typename: 'PageInfo',
    hasNextPage: lastIndex >= 0 && lastIndex < items.length - 1,
    hasPreviousPage: firstIndex > 0,
    startCursor: start,
    endCursor: end,
  };
}
function gqlPaginate<T>(items: readonly T[], args: Record<string, unknown>, key: (item: T) => string): T[] {
  let list = [...items];
  const after = typeof args.after === 'string' ? args.after : null;
  if (after) {
    const idx = list.findIndex((item) => gqlCursor(key(item)) === after);
    if (idx >= 0) list = list.slice(idx + 1);
  }
  const first = typeof args.first === 'number' && args.first >= 0 ? Math.trunc(args.first) : list.length;
  return list.slice(0, first);
}
function gqlConnection<T>(typeName: string, edgeType: string, items: readonly T[], args: Record<string, unknown>, key: (item: T) => string, wrap: (item: T) => Record<string, unknown>): Record<string, unknown> {
  const page = gqlPaginate(items, args, key);
  return {
    __typename: typeName,
    nodes: page.map(wrap),
    edges: page.map((item) => ({ __typename: edgeType, node: wrap(item), cursor: gqlCursor(key(item)) })),
    pageInfo: gqlPageInfo(items, page, key),
    totalCount: items.length,
  };
}
function findRepoById(id: number): Repo | undefined {
  for (const repo of store.repos.values()) if (repo.id === id) return repo;
  return undefined;
}
function gqlIssueState(issue: Issue): string {
  return issue.state === 'open' ? 'OPEN' : 'CLOSED';
}
function gqlPullState(pull: Pull): string {
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

function gqlResolveField(typeName: string, obj: Record<string, unknown>, field: GqlField, ctx: GqlCtx, variables: Record<string, unknown>): unknown {
  const args = gqlArgs(field, variables);
  if (field.name === '__typename') return typeName;
  switch (typeName) {
    case 'Query': {
      if (field.name === 'viewer') return gqlUserObj(VIEWER_LOGIN, VIEWER_ID, ctx.origin);
      if (field.name === 'repository') {
        const repo = store.getRepo(String(args.owner ?? ''), String(args.name ?? ''));
        return repo ? gqlRepoObj(repo) : null;
      }
      if (field.name === 'node') {
        const parsed = typeof args.id === 'string' ? parseGlobalId(args.id) : null;
        if (!parsed) return null;
        if (parsed.kind === 'R') {
          const repo = findRepoById(Number(parsed.key));
          return repo ? gqlRepoObj(repo) : null;
        }
        if (parsed.kind === 'I') {
          const [repoId, num] = parsed.key.split(':');
          const repo = findRepoById(Number(repoId));
          const issue = repo?.issues.find((i) => i.number === Number(num));
          return repo && issue ? gqlIssueObj(repo, issue) : null;
        }
        if (parsed.kind === 'P') {
          const [repoId, num] = parsed.key.split(':');
          const repo = findRepoById(Number(repoId));
          const pull = repo?.pulls.find((p) => p.number === Number(num));
          return repo && pull ? gqlPullObj(repo, pull) : null;
        }
        return null;
      }
      if (field.name === '__type') {
        const name = String(args.name ?? '');
        const fields = GQL_TYPE_FIELDS[name];
        const enums = GQL_ENUM_VALUES[name];
        return {
          __typename: '__Type',
          name,
          kind: enums ? 'ENUM' : 'OBJECT',
          description: null,
          fields: fields ? fields.map((n) => ({ __typename: '__Field', name: n, description: null, args: [] })) : null,
          enumValues: enums ? enums.map((n) => ({ __typename: '__EnumValue', name: n, description: null })) : null,
        };
      }
      if (field.name === '__schema') {
        return {
          __typename: '__Schema',
          queryType: { __typename: '__Type', name: 'Query' },
          mutationType: { __typename: '__Type', name: 'Mutation' },
          types: Object.keys(GQL_TYPE_FIELDS).map((n) => ({ __typename: '__Type', name: n })),
        };
      }
      throw new GqlError(`Cannot query field "${field.name}" on type "Query".`);
    }
    case 'Mutation': {
      if (field.name === 'createIssue') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const parsed = typeof input.repositoryId === 'string' ? parseGlobalId(input.repositoryId) : null;
        const repo = parsed?.kind === 'R' ? findRepoById(Number(parsed.key)) : undefined;
        if (!repo) throw new GqlError('Repository not found for createIssue.');
        const title = typeof input.title === 'string' ? input.title : '';
        if (!title) throw new GqlError('createIssue requires a title.');
        const now = tickIso();
        const issue: Issue = { id: allocId(), number: repo.nextNumber++, title, body: typeof input.body === 'string' ? input.body : '', state: 'open', labels: [], comments: [], createdAt: now, updatedAt: now, closedAt: null, seq: nextSeq() };
        repo.issues.push(issue);
        return { __typename: 'CreateIssuePayload', issue: gqlIssueObj(repo, issue), clientMutationId: input.clientMutationId ?? null };
      }
      if (field.name === 'closeIssue') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const parsed = typeof input.issueId === 'string' ? parseGlobalId(input.issueId) : null;
        if (parsed?.kind !== 'I') throw new GqlError('Issue not found for closeIssue.');
        const [repoId, num] = parsed.key.split(':');
        const repo = findRepoById(Number(repoId));
        const issue = repo?.issues.find((i) => i.number === Number(num));
        if (!repo || !issue) throw new GqlError('Issue not found for closeIssue.');
        issue.state = 'closed';
        issue.closedAt = tickIso();
        issue.updatedAt = tickIso();
        repo.issueJson.delete(issue.number);
        return { __typename: 'CloseIssuePayload', issue: gqlIssueObj(repo, issue), clientMutationId: input.clientMutationId ?? null };
      }
      if (field.name === 'createPullRequest') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const parsed = typeof input.repositoryId === 'string' ? parseGlobalId(input.repositoryId) : null;
        const repo = parsed?.kind === 'R' ? findRepoById(Number(parsed.key)) : undefined;
        if (!repo) throw new GqlError('Repository not found for createPullRequest.');
        const head = String(input.headRefName ?? '');
        const baseName = String(input.baseRefName ?? repo.defaultBranch);
        const headSha = repo.refs.get(`refs/heads/${head}`);
        const baseSha = repo.refs.get(`refs/heads/${baseName}`);
        if (!headSha || !baseSha) throw new GqlError('head or base branch does not exist for createPullRequest.');
        if (repo.pulls.some((p) => p.state === 'open' && p.head === head && p.base === baseName)) {
          throw new GqlError('A pull request already exists for this head and base.');
        }
        const now = tickIso();
        const pull: Pull = { id: allocId(), number: repo.nextNumber++, title: typeof input.title === 'string' ? input.title : '', body: typeof input.body === 'string' ? input.body : '', state: 'open', head, base: baseName, headSha, baseSha, merged: false, mergedAt: null, mergeSha: null, createdAt: now, updatedAt: now, closedAt: null, seq: nextSeq() };
        repo.pulls.push(pull);
        return { __typename: 'CreatePullRequestPayload', pullRequest: gqlPullObj(repo, pull), clientMutationId: input.clientMutationId ?? null };
      }
      if (field.name === 'mergePullRequest') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const parsed = typeof input.pullRequestId === 'string' ? parseGlobalId(input.pullRequestId) : null;
        if (parsed?.kind !== 'P') throw new GqlError('Pull request not found for mergePullRequest.');
        const [repoId, num] = parsed.key.split(':');
        const repo = findRepoById(Number(repoId));
        const pull = repo?.pulls.find((p) => p.number === Number(num));
        if (!repo || !pull) throw new GqlError('Pull request not found for mergePullRequest.');
        if (pull.state === 'closed') throw new GqlError('Pull request is already closed.');
        if (pullConflicts(repo, pull)) throw new GqlError('Merge conflict.');
        const mergeSha = squashMerge(repo, pull);
        const now = tickIso();
        pull.state = 'closed';
        pull.merged = true;
        pull.mergedAt = now;
        pull.mergeSha = mergeSha;
        pull.closedAt = now;
        pull.updatedAt = now;
        return { __typename: 'MergePullRequestPayload', pullRequest: gqlPullObj(repo, pull), clientMutationId: input.clientMutationId ?? null };
      }
      if (field.name === 'addComment') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const parsed = typeof input.subjectId === 'string' ? parseGlobalId(input.subjectId) : null;
        if (parsed?.kind !== 'I') throw new GqlError('Subject not found for addComment.');
        const [repoId, num] = parsed.key.split(':');
        const repo = findRepoById(Number(repoId));
        const issue = repo?.issues.find((i) => i.number === Number(num));
        if (!repo || !issue) throw new GqlError('Subject not found for addComment.');
        const now = tickIso();
        const comment: Comment = { id: allocId(), body: typeof input.body === 'string' ? input.body : '', createdAt: now, updatedAt: now };
        issue.comments.push(comment);
        issue.updatedAt = now;
        repo.issueJson.delete(issue.number);
        const node = { __typename: 'Comment', repo, issue, comment };
        return { __typename: 'AddCommentPayload', commentEdge: { __typename: 'CommentEdge', node, cursor: gqlCursor(String(comment.id)) }, clientMutationId: input.clientMutationId ?? null };
      }
      throw new GqlError(`Cannot query field "${field.name}" on type "Mutation".`);
    }
    case 'User': {
      if (field.name === 'login') return obj.login;
      if (field.name === 'id') return obj.id;
      if (field.name === 'name') return obj.name;
      if (field.name === 'email') return obj.email;
      if (field.name === 'avatarUrl') return obj.avatarUrl;
      if (field.name === 'url') return obj.url;
      if (field.name === 'repositories') {
        const repos = store.viewerRepos();
        return gqlConnection('RepositoryConnection', 'RepositoryEdge', repos, args, (r) => String(r.id), (r) => gqlRepoObj(r));
      }
      throw new GqlError(`Cannot query field "${field.name}" on type "User".`);
    }
    case 'Repository': {
      const repo = obj.repo as Repo;
      switch (field.name) {
        case 'id': return globalId('R', String(repo.id));
        case 'databaseId': return repo.id;
        case 'name': return repo.name;
        case 'nameWithOwner': return `${repo.owner}/${repo.name}`;
        case 'owner': return gqlUserObj(repo.owner, repo.owner === VIEWER_LOGIN ? VIEWER_ID : 0, ctx.origin);
        case 'description': return repo.description;
        case 'isPrivate': return repo.isPrivate;
        case 'isArchived': return false;
        case 'url': return `${ctx.origin}/${repo.owner}/${repo.name}`;
        case 'createdAt': return repo.createdAt;
        case 'updatedAt': return repo.updatedAt;
        case 'viewerPermission': return 'ADMIN';
        case 'hasIssuesEnabled': return true;
        case 'stargazerCount': return 0;
        case 'forkCount': return 0;
        case 'defaultBranchRef': {
          const sha = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
          return sha ? { __typename: 'Ref', name: repo.defaultBranch, prefix: 'refs/heads/', target: { __typename: 'Commit', oid: sha, message: '' } } : null;
        }
        case 'issue': {
          const issue = repo.issues.find((i) => i.number === Number(args.number));
          return issue ? gqlIssueObj(repo, issue) : null;
        }
        case 'issues': {
          let list = [...repo.issues];
          const states = Array.isArray(args.states) ? (args.states as string[]) : null;
          if (states) list = list.filter((i) => states.includes(gqlIssueState(i)));
          const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
          const direction = String(orderBy.direction ?? 'DESC');
          list.sort((a, b) => (direction === 'ASC' ? a.seq - b.seq : b.seq - a.seq));
          return gqlConnection('IssueConnection', 'IssueEdge', list, args, (i) => String(i.number), (i) => gqlIssueObj(repo, i));
        }
        case 'pullRequest': {
          const pull = repo.pulls.find((p) => p.number === Number(args.number));
          return pull ? gqlPullObj(repo, pull) : null;
        }
        case 'pullRequests': {
          let list = [...repo.pulls];
          const states = Array.isArray(args.states) ? (args.states as string[]) : null;
          if (states) list = list.filter((p) => states.includes(gqlPullState(p)));
          const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
          const direction = String(orderBy.direction ?? 'DESC');
          list.sort((a, b) => (direction === 'ASC' ? a.seq - b.seq : b.seq - a.seq));
          return gqlConnection('PullRequestConnection', 'PullRequestEdge', list, args, (p) => String(p.number), (p) => gqlPullObj(repo, p));
        }
        case 'labels': {
          return gqlConnection('LabelConnection', 'LabelEdge', repo.labels, args, (l) => l.name, (l) => ({ __typename: 'Label', repo, label: l }));
        }
        default: throw new GqlError(`Cannot query field "${field.name}" on type "Repository".`);
      }
    }
    case 'Issue': {
      const repo = obj.repo as Repo;
      const issue = obj.issue as Issue;
      switch (field.name) {
        case 'id': return globalId('I', `${repo.id}:${issue.number}`);
        case 'databaseId': return issue.id;
        case 'number': return issue.number;
        case 'title': return issue.title;
        case 'body': return issue.body;
        case 'state': return gqlIssueState(issue);
        case 'url': return `${ctx.origin}/${repo.owner}/${repo.name}/issues/${issue.number}`;
        case 'createdAt': return issue.createdAt;
        case 'updatedAt': return issue.updatedAt;
        case 'closedAt': return issue.closedAt;
        case 'author': return gqlUserObj(VIEWER_LOGIN, VIEWER_ID, ctx.origin);
        case 'repository': return gqlRepoObj(repo);
        case 'labels': return gqlConnection('LabelConnection', 'LabelEdge', issue.labels.map((name) => repo.labels.find((l) => l.name === name)).filter((l): l is Label => l !== undefined), args, (l) => l.name, (l) => ({ __typename: 'Label', repo, label: l }));
        case 'comments': return gqlConnection('CommentConnection', 'CommentEdge', issue.comments, args, (c) => String(c.id), (c) => ({ __typename: 'Comment', repo, issue, comment: c }));
        default: throw new GqlError(`Cannot query field "${field.name}" on type "Issue".`);
      }
    }
    case 'PullRequest': {
      const repo = obj.repo as Repo;
      const pull = obj.pull as Pull;
      switch (field.name) {
        case 'id': return globalId('P', `${repo.id}:${pull.number}`);
        case 'databaseId': return pull.id;
        case 'number': return pull.number;
        case 'title': return pull.title;
        case 'body': return pull.body;
        case 'state': return gqlPullState(pull);
        case 'headRefName': return pull.head;
        case 'baseRefName': return pull.base;
        case 'headRefOid': return pull.headSha;
        case 'baseRefOid': return pull.baseSha;
        case 'mergeable': return pullConflicts(repo, pull) ? 'CONFLICTING' : 'MERGEABLE';
        case 'merged': return pull.merged;
        case 'mergedAt': return pull.mergedAt;
        case 'mergeCommit': return pull.mergeSha ? { __typename: 'Commit', oid: pull.mergeSha, message: '' } : null;
        case 'author': return gqlUserObj(VIEWER_LOGIN, VIEWER_ID, ctx.origin);
        case 'repository': return gqlRepoObj(repo);
        case 'url': return `${ctx.origin}/${repo.owner}/${repo.name}/pull/${pull.number}`;
        case 'createdAt': return pull.createdAt;
        case 'updatedAt': return pull.updatedAt;
        case 'files': {
          const files = pullFiles(repo, pull);
          return gqlConnection('PullRequestFileConnection', 'PullRequestFileEdge', files, args, (f) => f.filename, (f) => ({ __typename: 'PullRequestFile', path: f.filename, additions: f.additions, deletions: f.deletions, changeType: f.status === 'added' ? 'ADDED' : f.status === 'removed' ? 'REMOVED' : 'MODIFIED' }));
        }
        case 'commits': {
          const commits = listCommits(repo, pull.headSha);
          return gqlConnection('CommitConnection', 'CommitEdge', commits, args, (c) => c.sha, (c) => ({ __typename: 'Commit', oid: c.sha, message: parseCommit(c.data).message }));
        }
        default: throw new GqlError(`Cannot query field "${field.name}" on type "PullRequest".`);
      }
    }
    case 'Label': {
      const label = obj.label as Label;
      if (field.name === 'id') return globalId('L', `${(obj.repo as Repo).id}:${label.name}`);
      if (field.name === 'name') return label.name;
      if (field.name === 'color') return label.color;
      if (field.name === 'description') return label.description;
      if (field.name === 'url') return `${ctx.origin}/api/v3/repos/${(obj.repo as Repo).owner}/${(obj.repo as Repo).name}/labels/${encodeURIComponent(label.name)}`;
      throw new GqlError(`Cannot query field "${field.name}" on type "Label".`);
    }
    case 'Comment': {
      const comment = obj.comment as Comment;
      if (field.name === 'id') return globalId('IC', `${(obj.repo as Repo).id}:${(obj.issue as Issue).number}:${comment.id}`);
      if (field.name === 'body') return comment.body;
      if (field.name === 'author') return gqlUserObj(VIEWER_LOGIN, VIEWER_ID, ctx.origin);
      if (field.name === 'createdAt') return comment.createdAt;
      if (field.name === 'updatedAt') return comment.updatedAt;
      if (field.name === 'url') return `${ctx.origin}/${(obj.repo as Repo).owner}/${(obj.repo as Repo).name}/issues/${(obj.issue as Issue).number}#issuecomment-${comment.id}`;
      throw new GqlError(`Cannot query field "${field.name}" on type "Comment".`);
    }
    case 'Ref': {
      if (field.name === 'name') return obj.name;
      if (field.name === 'prefix') return obj.prefix;
      if (field.name === 'target') return obj.target;
      throw new GqlError(`Cannot query field "${field.name}" on type "Ref".`);
    }
    case 'Commit': {
      if (field.name === 'oid') return obj.oid;
      if (field.name === 'message') return obj.message;
      // Reads must not advance the deterministic clock: actor dates are fixed.
      if (field.name === 'author') return { __typename: 'GitActor', name: VIEWER_NAME, email: VIEWER_EMAIL, date: '2025-01-01T00:00:00Z' };
      if (field.name === 'committer') return { __typename: 'GitActor', name: VIEWER_NAME, email: VIEWER_EMAIL, date: '2025-01-01T00:00:00Z' };
      throw new GqlError(`Cannot query field "${field.name}" on type "Commit".`);
    }
    case 'GitActor': {
      if (field.name === 'name') return obj.name;
      if (field.name === 'email') return obj.email;
      if (field.name === 'date') return obj.date;
      throw new GqlError(`Cannot query field "${field.name}" on type "GitActor".`);
    }
    case 'PullRequestFile': {
      if (field.name === 'path') return obj.path;
      if (field.name === 'additions') return obj.additions;
      if (field.name === 'deletions') return obj.deletions;
      if (field.name === 'changeType') return obj.changeType;
      throw new GqlError(`Cannot query field "${field.name}" on type "PullRequestFile".`);
    }
    case 'IssueConnection':
    case 'PullRequestConnection':
    case 'LabelConnection':
    case 'CommentConnection':
    case 'PullRequestFileConnection':
    case 'CommitConnection':
    case 'RepositoryConnection': {
      if (field.name === 'nodes') return obj.nodes;
      if (field.name === 'edges') return obj.edges;
      if (field.name === 'pageInfo') return obj.pageInfo;
      if (field.name === 'totalCount') return obj.totalCount;
      throw new GqlError(`Cannot query field "${field.name}" on type "${typeName}".`);
    }
    case 'IssueEdge':
    case 'PullRequestEdge':
    case 'LabelEdge':
    case 'CommentEdge':
    case 'PullRequestFileEdge':
    case 'CommitEdge':
    case 'RepositoryEdge': {
      if (field.name === 'node') return obj.node;
      if (field.name === 'cursor') return obj.cursor;
      throw new GqlError(`Cannot query field "${field.name}" on type "${typeName}".`);
    }
    case 'PageInfo': {
      if (field.name === 'hasNextPage') return obj.hasNextPage;
      if (field.name === 'hasPreviousPage') return obj.hasPreviousPage;
      if (field.name === 'startCursor') return obj.startCursor;
      if (field.name === 'endCursor') return obj.endCursor;
      throw new GqlError(`Cannot query field "${field.name}" on type "PageInfo".`);
    }
    case '__Type': {
      if (field.name === 'name') return obj.name;
      if (field.name === 'kind') return obj.kind;
      if (field.name === 'description') return obj.description;
      if (field.name === 'fields') return obj.fields;
      if (field.name === 'enumValues') return obj.enumValues;
      throw new GqlError(`Cannot query field "${field.name}" on type "__Type".`);
    }
    case '__Field': {
      if (field.name === 'name') return obj.name;
      if (field.name === 'description') return obj.description;
      if (field.name === 'args') return obj.args;
      throw new GqlError(`Cannot query field "${field.name}" on type "__Field".`);
    }
    case '__EnumValue': {
      if (field.name === 'name') return obj.name;
      if (field.name === 'description') return obj.description;
      throw new GqlError(`Cannot query field "${field.name}" on type "__EnumValue".`);
    }
    case '__Schema': {
      if (field.name === 'queryType') return obj.queryType;
      if (field.name === 'mutationType') return obj.mutationType;
      if (field.name === 'types') return obj.types;
      throw new GqlError(`Cannot query field "${field.name}" on type "__Schema".`);
    }
    case 'CreateIssuePayload':
    case 'CloseIssuePayload':
    case 'CreatePullRequestPayload':
    case 'MergePullRequestPayload':
    case 'AddCommentPayload': {
      if (field.name === 'issue') return obj.issue;
      if (field.name === 'pullRequest') return obj.pullRequest;
      if (field.name === 'commentEdge') return obj.commentEdge;
      if (field.name === 'clientMutationId') return obj.clientMutationId;
      throw new GqlError(`Cannot query field "${field.name}" on type "${typeName}".`);
    }
    default:
      throw new GqlError(`Cannot query field "${field.name}" on type "${typeName}".`);
  }
}

/** Execute a selection set against an object of the given type. */
function gqlExecuteSelection(typeName: string, obj: Record<string, unknown>, selection: GqlSelection[], ctx: GqlCtx, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selection) {
    if (sel.kind === 'inline') {
      if (sel.typeCondition === null || sel.typeCondition === typeName) {
        Object.assign(out, gqlExecuteSelection(typeName, obj, sel.selection, ctx, variables));
      }
      continue;
    }
    if (sel.kind === 'spread') {
      const frag = ctx.fragments.get(sel.name);
      if (frag) Object.assign(out, gqlExecuteSelection(typeName, obj, frag, ctx, variables));
      continue;
    }
    const field = sel;
    try {
      const value = gqlResolveField(typeName, obj, field, ctx, variables);
      if (field.selection && value !== null && value !== undefined) {
        if (Array.isArray(value)) {
          out[field.alias] = value.map((item) => {
            if (item && typeof item === 'object' && '__typename' in (item as Record<string, unknown>)) {
              const rec = item as Record<string, unknown>;
              return gqlExecuteSelection(String(rec.__typename), rec, field.selection!, ctx, variables);
            }
            return item;
          });
        } else if (typeof value === 'object' && '__typename' in (value as Record<string, unknown>)) {
          const rec = value as Record<string, unknown>;
          out[field.alias] = gqlExecuteSelection(String(rec.__typename), rec, field.selection, ctx, variables);
        } else {
          out[field.alias] = value;
        }
      } else {
        out[field.alias] = value ?? null;
      }
    } catch (err) {
      ctx.errors.push(err instanceof Error ? err.message : String(err));
      out[field.alias] = null;
    }
  }
  return out;
}

function gqlExecuteOne(doc: GqlDocument, query: string, variables: Record<string, unknown>, origin: string): Record<string, unknown> {
  const ctx: GqlCtx = { origin, errors: [], fragments: doc.fragments };
  let data: Record<string, unknown> = {};
  try {
    const parser = new GqlParser(query);
    const parsed = parser.parseDocument();
    ctx.fragments = parsed.fragments;
    const op = parsed.operations[0];
    if (!op) throw new GqlError('GraphQL document contains no operation.');
    const rootType = op.type === 'mutation' ? 'Mutation' : 'Query';
    data = gqlExecuteSelection(rootType, { __typename: rootType }, op.selection, ctx, variables);
  } catch (err) {
    ctx.errors.push(err instanceof Error ? err.message : String(err));
  }
  const result: Record<string, unknown> = { data };
  if (ctx.errors.length > 0) result.errors = ctx.errors.map((message) => ({ message }));
  return result;
}

function handleGraphQL(body: unknown, origin: string): RestResp {
  if (Array.isArray(body)) {
    const results = body.map((item) => {
      const entry = (item ?? {}) as Record<string, unknown>;
      if (typeof entry.query !== 'string') return { data: {}, errors: [{ message: 'GraphQL request must include a query string.' }] };
      try {
        const doc = new GqlParser(entry.query).parseDocument();
        return gqlExecuteOne(doc, entry.query, (entry.variables ?? {}) as Record<string, unknown>, origin);
      } catch (err) {
        return { data: {}, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
      }
    });
    return restJson(200, results);
  }
  const entry = (body ?? {}) as Record<string, unknown>;
  if (typeof entry.query !== 'string') {
    return restJson(200, { data: {}, errors: [{ message: 'GraphQL request must include a query string.' }] });
  }
  try {
    const doc = new GqlParser(entry.query).parseDocument();
    return restJson(200, gqlExecuteOne(doc, entry.query, (entry.variables ?? {}) as Record<string, unknown>, origin));
  } catch (err) {
    return restJson(200, { data: {}, errors: [{ message: err instanceof Error ? err.message : String(err) }] });
  }
}

// ---------------------------------------------------------------------------
// MCP (Streamable HTTP, JSON-RPC 2.0, revision 2026-07-28)
// ---------------------------------------------------------------------------

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: { type: string; properties: Record<string, unknown>; required: string[] };
}
const MCP_TOOLS: McpToolDef[] = Object.freeze([
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Repository name' }, description: { type: 'string', description: 'Repository description' }, private: { type: 'boolean', description: 'Whether the repository is private' } }, required: ['name'] },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' } }, required: ['owner', 'repo'] },
  },
  {
    name: 'list_repos',
    description: 'List repositories owned by the authenticated user.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Issue title' }, body: { type: 'string', description: 'Issue body' }, labels: { type: 'array', items: { type: 'string' }, description: 'Label names' } }, required: ['owner', 'repo', 'title'] },
  },
  {
    name: 'get_issue',
    description: 'Get an issue by number.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, issue_number: { type: 'integer', description: 'Issue number' } }, required: ['owner', 'repo', 'issue_number'] },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, state: { type: 'string', description: 'Issue state: open, closed, or all' } }, required: ['owner', 'repo'] },
  },
  {
    name: 'update_issue',
    description: 'Update an issue: close, reopen, or edit its title or body.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, issue_number: { type: 'integer', description: 'Issue number' }, state: { type: 'string', description: 'New state: open or closed' }, title: { type: 'string', description: 'New title' }, body: { type: 'string', description: 'New body' } }, required: ['owner', 'repo', 'issue_number'] },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch into a base branch.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Pull request title' }, head: { type: 'string', description: 'Head branch name' }, base: { type: 'string', description: 'Base branch name' }, body: { type: 'string', description: 'Pull request body' } }, required: ['owner', 'repo', 'title', 'head', 'base'] },
  },
  {
    name: 'get_pull_request',
    description: 'Get a pull request by number.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, pull_number: { type: 'integer', description: 'Pull request number' } }, required: ['owner', 'repo', 'pull_number'] },
  },
  {
    name: 'list_pull_requests',
    description: 'List pull requests in a repository.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, state: { type: 'string', description: 'Pull request state: open, closed, or all' } }, required: ['owner', 'repo'] },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request into its base branch.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, pull_number: { type: 'integer', description: 'Pull request number' } }, required: ['owner', 'repo', 'pull_number'] },
  },
]);

function mcpRepoSummary(repo: Repo, origin: string): Record<string, unknown> {
  const full = repoJson(repo, origin);
  return {
    id: full.id,
    node_id: full.node_id,
    name: full.name,
    full_name: full.full_name,
    owner: { login: repo.owner, id: repo.owner === VIEWER_LOGIN ? VIEWER_ID : 0 },
    private: full.private,
    description: full.description,
    default_branch: full.default_branch,
    html_url: full.html_url,
    clone_url: full.clone_url,
    created_at: full.created_at,
    updated_at: full.updated_at,
  };
}
function mcpIssueSummary(repo: Repo, issue: Issue, origin: string): Record<string, unknown> {
  const full = issueJson(repo, issue, origin);
  return { id: full.id, node_id: full.node_id, number: full.number, title: full.title, body: full.body, state: full.state, labels: (full.labels as Array<Record<string, unknown>>).map((l) => l.name), comments: full.comments, created_at: full.created_at, updated_at: full.updated_at, closed_at: full.closed_at, url: full.url, html_url: full.html_url };
}
function mcpPullSummary(repo: Repo, pull: Pull, origin: string): Record<string, unknown> {
  const full = pullJson(repo, pull, origin);
  return { id: full.id, node_id: full.node_id, number: full.number, title: full.title, body: full.body, state: full.state, head: { ref: pull.head, sha: pull.headSha }, base: { ref: pull.base, sha: pull.baseSha }, merged: full.merged, merged_at: full.merged_at, merge_commit_sha: full.merge_commit_sha, created_at: full.created_at, updated_at: full.updated_at, closed_at: full.closed_at, url: full.url, html_url: full.html_url };
}

class McpError extends Error {
  code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

function mcpFindRepo(args: Record<string, unknown>): Repo {
  const owner = String(args.owner ?? '');
  const repoName = String(args.repo ?? '');
  const repo = store.getRepo(owner, repoName);
  if (!repo) throw new McpError(-32602, `Repository not found: ${owner}/${repoName}`);
  return repo;
}
function mcpRequire(args: Record<string, unknown>, names: readonly string[]): void {
  for (const name of names) {
    if (args[name] === undefined || args[name] === null || args[name] === '') {
      throw new McpError(-32602, `Missing required argument: ${name}`);
    }
  }
}

function mcpCallTool(name: string, args: Record<string, unknown>, origin: string): Record<string, unknown> {
  switch (name) {
    case 'create_repo': {
      mcpRequire(args, ['name']);
      const repoName = String(args.name);
      if (!/^[A-Za-z0-9._-]+$/.test(repoName)) throw new McpError(-32602, 'name is invalid');
      if (store.getRepo(VIEWER_LOGIN, repoName)) throw new McpError(-32602, `Repository ${VIEWER_LOGIN}/${repoName} already exists`);
      const repo = store.createRepo(VIEWER_LOGIN, repoName, typeof args.description === 'string' ? args.description : '', args.private === true);
      return mcpRepoSummary(repo, origin);
    }
    case 'get_repo': {
      mcpRequire(args, ['owner', 'repo']);
      return mcpRepoSummary(mcpFindRepo(args), origin);
    }
    case 'list_repos': {
      return { repos: store.viewerRepos().map((r) => mcpRepoSummary(r, origin)) };
    }
    case 'create_issue': {
      mcpRequire(args, ['owner', 'repo', 'title']);
      const repo = mcpFindRepo(args);
      const labelNames: string[] = Array.isArray(args.labels) ? args.labels.map((l) => String(l)) : [];
      for (const labelName of labelNames) {
        if (!repo.labels.some((l) => l.name === labelName)) throw new McpError(-32602, `Label does not exist: ${labelName}`);
      }
      const now = tickIso();
      const issue: Issue = { id: allocId(), number: repo.nextNumber++, title: String(args.title), body: typeof args.body === 'string' ? args.body : '', state: 'open', labels: labelNames, comments: [], createdAt: now, updatedAt: now, closedAt: null, seq: nextSeq() };
      repo.issues.push(issue);
      return mcpIssueSummary(repo, issue, origin);
    }
    case 'get_issue': {
      mcpRequire(args, ['owner', 'repo', 'issue_number']);
      const repo = mcpFindRepo(args);
      const issue = repo.issues.find((i) => i.number === Number(args.issue_number));
      if (!issue) throw new McpError(-32602, `Issue not found: ${args.issue_number}`);
      return mcpIssueSummary(repo, issue, origin);
    }
    case 'list_issues': {
      mcpRequire(args, ['owner', 'repo']);
      const repo = mcpFindRepo(args);
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = repo.issues.filter((i) => (state === 'all' ? true : i.state === state)).sort((a, b) => b.seq - a.seq);
      return { issues: list.map((i) => mcpIssueSummary(repo, i, origin)) };
    }
    case 'update_issue': {
      mcpRequire(args, ['owner', 'repo', 'issue_number']);
      const repo = mcpFindRepo(args);
      const issue = repo.issues.find((i) => i.number === Number(args.issue_number));
      if (!issue) throw new McpError(-32602, `Issue not found: ${args.issue_number}`);
      if (typeof args.title === 'string') issue.title = args.title;
      if (typeof args.body === 'string') issue.body = args.body;
      if (args.state === 'open' || args.state === 'closed') {
        issue.state = args.state;
        issue.closedAt = args.state === 'closed' ? tickIso() : null;
      }
      issue.updatedAt = tickIso();
      repo.issueJson.delete(issue.number);
      return mcpIssueSummary(repo, issue, origin);
    }
    case 'create_pull_request': {
      mcpRequire(args, ['owner', 'repo', 'title', 'head', 'base']);
      const repo = mcpFindRepo(args);
      const head = String(args.head);
      const baseName = String(args.base);
      const headSha = repo.refs.get(`refs/heads/${head}`);
      const baseSha = repo.refs.get(`refs/heads/${baseName}`);
      if (!headSha || !baseSha) throw new McpError(-32602, 'head or base branch does not exist');
      if (repo.pulls.some((p) => p.state === 'open' && p.head === head && p.base === baseName)) {
        throw new McpError(-32602, 'A pull request already exists for this head and base');
      }
      const now = tickIso();
      const pull: Pull = { id: allocId(), number: repo.nextNumber++, title: String(args.title), body: typeof args.body === 'string' ? args.body : '', state: 'open', head, base: baseName, headSha, baseSha, merged: false, mergedAt: null, mergeSha: null, createdAt: now, updatedAt: now, closedAt: null, seq: nextSeq() };
      repo.pulls.push(pull);
      return mcpPullSummary(repo, pull, origin);
    }
    case 'get_pull_request': {
      mcpRequire(args, ['owner', 'repo', 'pull_number']);
      const repo = mcpFindRepo(args);
      const pull = repo.pulls.find((p) => p.number === Number(args.pull_number));
      if (!pull) throw new McpError(-32602, `Pull request not found: ${args.pull_number}`);
      return mcpPullSummary(repo, pull, origin);
    }
    case 'list_pull_requests': {
      mcpRequire(args, ['owner', 'repo']);
      const repo = mcpFindRepo(args);
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = repo.pulls.filter((p) => (state === 'all' ? true : p.state === state)).sort((a, b) => b.seq - a.seq);
      return { pull_requests: list.map((p) => mcpPullSummary(repo, p, origin)) };
    }
    case 'merge_pull_request': {
      mcpRequire(args, ['owner', 'repo', 'pull_number']);
      const repo = mcpFindRepo(args);
      const pull = repo.pulls.find((p) => p.number === Number(args.pull_number));
      if (!pull) throw new McpError(-32602, `Pull request not found: ${args.pull_number}`);
      if (pull.state === 'closed') throw new McpError(-32602, 'Pull request is already closed');
      if (pullConflicts(repo, pull)) throw new McpError(-32602, 'Merge conflict');
      const mergeSha = squashMerge(repo, pull);
      const now = tickIso();
      pull.state = 'closed';
      pull.merged = true;
      pull.mergedAt = now;
      pull.mergeSha = mergeSha;
      pull.closedAt = now;
      pull.updatedAt = now;
      return { merged: true, sha: mergeSha, number: pull.number, message: `Merge pull request #${pull.number} from ${repo.owner}/${pull.head}` };
    }
    default:
      throw new McpError(-32602, `Unknown tool: ${name}`);
  }
}

function handleMcpJson(body: unknown, origin: string): { status: number; body: string } {
  const envelope = (id: unknown, result: unknown): string =>
    JSON.stringify({ jsonrpc: '2.0', id: id ?? null, result });
  const errorEnvelope = (id: unknown, code: number, message: string): string =>
    JSON.stringify({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
  const req = (body ?? {}) as Record<string, unknown>;
  const id = req.id;
  // Notifications (no id) are acknowledged with an empty 202.
  if (id === undefined || id === null) return { status: 202, body: '' };
  const method = typeof req.method === 'string' ? req.method : '';
  if (method === 'server/discover') {
    const serverInfo = { name: FORGE_NAME, version: FORGE_VERSION };
    return { status: 200, body: envelope(id, { supportedVersions: ['2026-07-28', '2025-11-25'], capabilities: { tools: {} }, serverInfo, _meta: { 'io.modelcontextprotocol/serverInfo': serverInfo } }) };
  }
  if (method === 'initialize') {
    const params = (req.params ?? {}) as Record<string, unknown>;
    const protocolVersion = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2026-07-28';
    return { status: 200, body: envelope(id, { protocolVersion, capabilities: { tools: {} }, serverInfo: { name: FORGE_NAME, version: FORGE_VERSION } }) };
  }
  if (method === 'ping') return { status: 200, body: envelope(id, {}) };
  if (method === 'tools/list') return { status: 200, body: envelope(id, { tools: MCP_TOOLS }) };
  if (method === 'tools/call') {
    const params = (req.params ?? {}) as Record<string, unknown>;
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    try {
      const output = mcpCallTool(toolName, args, origin);
      const text = JSON.stringify(output);
      return { status: 200, body: envelope(id, { content: [{ type: 'text', text }], structuredContent: output }) };
    } catch (err) {
      if (err instanceof McpError) return { status: 200, body: errorEnvelope(id, err.code, err.message) };
      return { status: 200, body: errorEnvelope(id, -32603, err instanceof Error ? err.message : String(err)) };
    }
  }
  return { status: 200, body: errorEnvelope(id, -32601, `Method not found: ${method}`) };
}

/** Non-JSON bodies: HTTP 400 with a JSON-RPC parse error (-32700). */
function handleMcpParseError(rawText: string): { status: number; body: string } {
  let id: unknown = null;
  const m = /"id"\s*:\s*("[^"]*"|\d+)/.exec(rawText);
  if (m) {
    try {
      id = JSON.parse(m[1]!);
    } catch {
      id = null;
    }
  }
  return { status: 400, body: JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32700, message: 'Parse error' } }) };
}

// ---------------------------------------------------------------------------
// web UI (server-rendered; the suite never needs it, humans do)
// ---------------------------------------------------------------------------

function htmlPage(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escHtml(title)} · keystone</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:880px;margin:0 auto;padding:24px;color:#1f2328;background:#fff}a{color:#0969da;text-decoration:none}a:hover{text-decoration:underline}header{border-bottom:1px solid #d0d7de;padding-bottom:12px;margin-bottom:20px}h1{font-size:22px;margin:0}h2{font-size:16px;margin:24px 0 8px}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #d0d7de;padding:6px 8px;text-align:left;font-size:14px}code{background:#f6f8fa;padding:2px 5px;border-radius:4px;font-size:13px}pre{background:#f6f8fa;padding:12px;border-radius:6px;overflow:auto;font-size:13px}.muted{color:#656d76}.pill{display:inline-block;border:1px solid #d0d7de;border-radius:999px;padding:1px 8px;font-size:12px;margin-right:6px}.open{color:#1a7f37}.closed{color:#8250df}</style>
</head><body><header><h1><a href="/">keystone</a> <span class="muted">/ a GitHub-compatible git forge</span></h1></header>
${body}
<footer class="muted" style="margin-top:32px;border-top:1px solid #d0d7de;padding-top:12px;font-size:12px">keystone ${FORGE_VERSION} · git smart HTTP · REST v3 · GraphQL v4 · MCP</footer>
</body></html>`;
}

function handleWeb(method: string, segments: string[], query: URLSearchParams, origin: string): { status: number; body: string } {
  if (method !== 'GET') return { status: 404, body: htmlPage('Not found', '<p>Not found.</p>') };
  if (segments.length === 0) {
    const repos = store.viewerRepos();
    const rows = repos.map((r) => `<tr><td><a href="/${escHtml(r.owner)}/${escHtml(r.name)}">${escHtml(r.owner)}/${escHtml(r.name)}</a></td><td>${escHtml(r.description)}</td><td>${r.issues.filter((i) => i.state === 'open').length} open issues</td><td>${r.pulls.filter((p) => p.state === 'open').length} open PRs</td></tr>`).join('');
    return { status: 200, body: htmlPage('Repositories', `<h2>Repositories</h2><table><tr><th>Repository</th><th>Description</th><th>Issues</th><th>Pull requests</th></tr>${rows || '<tr><td colspan="4" class="muted">No repositories yet.</td></tr>'}</table><p class="muted">Clone with <code>git clone ${escHtml(origin)}/${VIEWER_LOGIN}/&lt;repo&gt;.git</code></p>`) };
  }
  const owner = segments[0]!;
  const repoName = segments[1] ?? '';
  const repo = repoName ? store.getRepo(owner, repoName) : undefined;
  if (!repo) return { status: 404, body: htmlPage('Not found', '<p>Repository not found.</p>') };
  const rest = segments.slice(2);
  const headSha = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (rest.length === 0) {
    const files = fileMapOf(repo, headSha);
    const rows = [...files.keys()].sort().map((p) => `<tr><td><a href="/${escHtml(owner)}/${escHtml(repoName)}/blob/${repo.defaultBranch}/${escHtml(p)}">${escHtml(p)}</a></td></tr>`).join('');
    const commits = listCommits(repo, headSha, 10).map((c) => `<tr><td><code>${c.sha.slice(0, 7)}</code></td><td><a href="/${escHtml(owner)}/${escHtml(repoName)}/commit/${c.sha}">${escHtml(parseCommit(c.data).message.split('\n')[0] ?? '')}</a></td></tr>`).join('');
    return { status: 200, body: htmlPage(`${owner}/${repoName}`, `<h2>${escHtml(owner)}/${escHtml(repoName)}</h2><p>${escHtml(repo.description || '')}</p><p><span class="pill">${escHtml(repo.defaultBranch)}</span><code>git clone ${escHtml(origin)}/${escHtml(owner)}/${escHtml(repoName)}.git</code></p><p><a href="/${escHtml(owner)}/${escHtml(repoName)}/issues">Issues (${repo.issues.length})</a> · <a href="/${escHtml(owner)}/${escHtml(repoName)}/pulls">Pull requests (${repo.pulls.length})</a></p><h2>Files</h2><table>${rows || '<tr><td class="muted">Empty repository.</td></tr>'}</table><h2>Recent commits</h2><table>${commits || '<tr><td class="muted">No commits yet.</td></tr>'}</table>`) };
  }
  if (rest[0] === 'issues' && rest.length === 1) {
    const rows = [...repo.issues].sort((a, b) => b.seq - a.seq).map((i) => `<tr><td><span class="${i.state}">${i.state}</span></td><td><a href="/${escHtml(owner)}/${escHtml(repoName)}/issues/${i.number}">#${i.number} ${escHtml(i.title)}</a></td><td>${escHtml(i.createdAt.slice(0, 10))}</td></tr>`).join('');
    return { status: 200, body: htmlPage(`Issues · ${owner}/${repoName}`, `<h2>Issues · ${escHtml(owner)}/${escHtml(repoName)}</h2><table>${rows || '<tr><td class="muted">No issues.</td></tr>'}</table>`) };
  }
  if (rest[0] === 'issues' && rest.length === 2) {
    const issue = repo.issues.find((i) => i.number === Number(rest[1]));
    if (!issue) return { status: 404, body: htmlPage('Not found', '<p>Issue not found.</p>') };
    const comments = issue.comments.map((c) => `<p><strong>${VIEWER_LOGIN}</strong> <span class="muted">${escHtml(c.createdAt)}</span><br>${escHtml(c.body)}</p>`).join('');
    return { status: 200, body: htmlPage(`#${issue.number} ${issue.title}`, `<h2>#${issue.number} ${escHtml(issue.title)}</h2><p><span class="${issue.state}">${issue.state}</span> · ${escHtml(issue.createdAt)}</p><pre>${escHtml(issue.body)}</pre><h2>Comments (${issue.comments.length})</h2>${comments || '<p class="muted">No comments.</p>'}`) };
  }
  if (rest[0] === 'pulls' && rest.length === 1) {
    const rows = [...repo.pulls].sort((a, b) => b.seq - a.seq).map((p) => `<tr><td><span class="${p.state}">${p.state}</span></td><td><a href="/${escHtml(owner)}/${escHtml(repoName)}/pull/${p.number}">#${p.number} ${escHtml(p.title)}</a></td><td>${escHtml(p.head)} → ${escHtml(p.base)}</td></tr>`).join('');
    return { status: 200, body: htmlPage(`Pull requests · ${owner}/${repoName}`, `<h2>Pull requests · ${escHtml(owner)}/${escHtml(repoName)}</h2><table>${rows || '<tr><td class="muted">No pull requests.</td></tr>'}</table>`) };
  }
  if (rest[0] === 'pull' && rest.length === 2) {
    const pull = repo.pulls.find((p) => p.number === Number(rest[1]));
    if (!pull) return { status: 404, body: htmlPage('Not found', '<p>Pull request not found.</p>') };
    const files = pullFiles(repo, pull).map((f) => `<tr><td>${escHtml(f.filename)}</td><td>${f.status}</td><td>+${f.additions} −${f.deletions}</td></tr>`).join('');
    return { status: 200, body: htmlPage(`#${pull.number} ${pull.title}`, `<h2>#${pull.number} ${escHtml(pull.title)}</h2><p><span class="${pull.state}">${pull.state}</span> · ${escHtml(pull.head)} → ${escHtml(pull.base)}${pull.merged ? ` · merged ${escHtml(pull.mergeSha?.slice(0, 7) ?? '')}` : ''}</p><pre>${escHtml(pull.body)}</pre><h2>Files changed</h2><table>${files || '<tr><td class="muted">No files changed.</td></tr>'}</table>`) };
  }
  if (rest[0] === 'blob' && rest.length >= 3) {
    const branch = rest[1]!;
    const path = rest.slice(2).join('/');
    const files = fileMapOf(repo, repo.refs.get(`refs/heads/${branch}`));
    const oid = files.get(path);
    if (!oid) return { status: 404, body: htmlPage('Not found', '<p>File not found.</p>') };
    const text = repo.objects.get(oid)!.data.toString('utf8');
    return { status: 200, body: htmlPage(`${path} · ${owner}/${repoName}`, `<h2>${escHtml(path)}</h2><p class="muted">${escHtml(branch)} · ${escHtml(oid.slice(0, 7))}</p><pre>${escHtml(text)}</pre>`) };
  }
  if (rest[0] === 'commit' && rest.length === 2) {
    const obj = repo.objects.get(rest[1]!);
    if (!obj || obj.type !== 'commit') return { status: 404, body: htmlPage('Not found', '<p>Commit not found.</p>') };
    const view = parseCommit(obj.data);
    const files = fileMapOf(repo, rest[1]);
    const rows = [...files.keys()].sort().map((p) => `<tr><td>${escHtml(p)}</td></tr>`).join('');
    return { status: 200, body: htmlPage(`Commit ${rest[1]!.slice(0, 7)}`, `<h2><code>${escHtml(rest[1]!)}</code></h2><pre>${escHtml(view.message)}</pre><p class="muted">${escHtml(view.author)}</p><h2>Files</h2><table>${rows}</table>`) };
  }
  return { status: 404, body: htmlPage('Not found', '<p>Not found.</p>') };
}

// ---------------------------------------------------------------------------
// HTTP server, routing, auth, lifecycle
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function requestOrigin(req: IncomingMessage): string {
  const host = req.headers.host ?? '127.0.0.1';
  return `http://${host}`;
}

/** Bearer auth: exact match when the trial token is set, any non-empty Bearer otherwise. */
function isAuthorized(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  const expected = process.env.MAKEFUN_SHOP_TOKEN;
  if (expected) return header === `Bearer ${expected}`;
  return header.startsWith('Bearer ') && header.length > 7;
}

function sendJson(res: ServerResponse, status: number, value: unknown, extraHeaders?: Record<string, string>): void {
  const body = typeof value === 'string' ? value : JSON.stringify(value);
  res.writeHead(status, { 'content-type': 'application/json', 'x-github-request-id': requestId(), ...(extraHeaders ?? {}) });
  res.end(body);
}
function sendBuffer(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, { 'content-type': contentType, 'x-github-request-id': requestId(), 'content-length': String(body.length) });
  res.end(body);
}

const GIT_ROUTE = /^\/([^/]+)\/([^/]+)\.git(?:\/(.*))?$/;

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const pathname = url.pathname;
  const segments = pathname.split('/').filter((s) => s !== '');
  const origin = requestOrigin(req);
  try {
    if (pathname === '/healthz') {
      sendJson(res, 200, { ok: true });
      return;
    }
    if (pathname === '/api/graphql') {
      if (!isAuthorized(req)) {
        sendJson(res, 401, { message: 'Requires authentication' });
        return;
      }
      if (req.method !== 'POST') {
        sendJson(res, 404, { message: 'Not Found' });
        return;
      }
      const raw = await readBody(req);
      let body: unknown = null;
      try {
        body = raw.length > 0 ? JSON.parse(raw.toString('utf8')) : null;
      } catch {
        sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      const out = handleGraphQL(body, origin);
      sendJson(res, out.status, out.body, out.headers);
      return;
    }
    if (pathname === '/mcp') {
      if (!isAuthorized(req)) {
        sendJson(res, 401, { message: 'Requires authentication' });
        return;
      }
      if (req.method !== 'POST') {
        sendJson(res, 404, { message: 'Not Found' });
        return;
      }
      const raw = await readBody(req);
      let body: unknown;
      try {
        body = raw.length > 0 ? JSON.parse(raw.toString('utf8')) : null;
      } catch {
        const err = handleMcpParseError(raw.toString('utf8'));
        sendJson(res, err.status, err.body);
        return;
      }
      const out = handleMcpJson(body, origin);
      sendJson(res, out.status, out.body);
      return;
    }
    if (segments[0] === 'api' && segments[1] === 'v3') {
      if (!isAuthorized(req)) {
        sendJson(res, 401, { message: 'Requires authentication' });
        return;
      }
      let body: unknown = null;
      if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE') {
        const raw = await readBody(req);
        if (raw.length > 0) {
          try {
            body = JSON.parse(raw.toString('utf8'));
          } catch {
            sendJson(res, 400, { message: 'Problems parsing JSON' });
            return;
          }
        }
      }
      const out = handleRest(req.method ?? 'GET', segments, url.searchParams, body, origin, pathname);
      sendJson(res, out.status, out.body, out.headers);
      return;
    }
    const gitMatch = GIT_ROUTE.exec(pathname);
    if (gitMatch) {
      const owner = decodeURIComponent(gitMatch[1]!);
      const repoName = decodeURIComponent(gitMatch[2]!);
      const restPath = gitMatch[3] ?? '';
      const repo = store.getRepo(owner, repoName);
      if (!repo) {
        sendBuffer(res, 404, 'text/plain; charset=utf-8', Buffer.from('repository not found\n', 'utf8'));
        return;
      }
      if (req.method === 'GET' && restPath === 'info/refs') {
        const service = url.searchParams.get('service') ?? '';
        const isV2 = (req.headers['git-protocol'] ?? '').includes('version=2');
        if (service === 'git-upload-pack') {
          const body = isV2 ? advertiseUploadV2() : advertiseUploadV0(repo);
          sendBuffer(res, 200, 'application/x-git-upload-pack-advertisement', body);
          return;
        }
        if (service === 'git-receive-pack') {
          sendBuffer(res, 200, 'application/x-git-receive-pack-advertisement', advertiseReceive(repo));
          return;
        }
        sendBuffer(res, 403, 'text/plain; charset=utf-8', Buffer.from('dumb HTTP protocol is not supported\n', 'utf8'));
        return;
      }
      if (req.method === 'POST' && restPath === 'git-upload-pack') {
        const raw = await readBody(req);
        const isV2 = (req.headers['git-protocol'] ?? '').includes('version=2');
        const out = handleUploadPack(repo, raw, isV2);
        sendBuffer(res, out.status, out.contentType, out.body);
        return;
      }
      if (req.method === 'POST' && restPath === 'git-receive-pack') {
        const raw = await readBody(req);
        const out = handleReceivePack(repo, raw);
        sendBuffer(res, out.status, out.contentType, out.body);
        return;
      }
      sendBuffer(res, 404, 'text/plain; charset=utf-8', Buffer.from('not found\n', 'utf8'));
      return;
    }
    const web = handleWeb(req.method ?? 'GET', segments.map((s) => decodeURIComponent(s)), url.searchParams, origin);
    res.writeHead(web.status, { 'content-type': 'text/html; charset=utf-8', 'x-github-request-id': requestId() });
    res.end(web.body);
  } catch (err) {
    console.error('keystone error:', err instanceof Error ? err.message : String(err));
    if (!res.headersSent) sendJson(res, 500, { message: 'Internal Server Error' });
    else res.end();
  }
}

async function main(): Promise<void> {
  const envUrl = process.env.MAKEFUN_ENV_URL;
  const port = envUrl ? 0 : Number(process.env.PORT ?? 8080);
  const server: Server = createServer((req, res) => {
    void handleRequest(req, res);
  });
  await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));
  const address = server.address();
  const actualPort = typeof address === 'object' && address !== null ? address.port : port;
  if (!envUrl) {
    console.log(`keystone ${FORGE_VERSION} listening on http://127.0.0.1:${actualPort}`);
    return;
  }
  const register = await fetch(`${envUrl}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ port: actualPort }),
  });
  if (!register.ok) {
    console.error(`keystone: register failed with HTTP ${register.status}`);
    process.exit(1);
  }
  for (;;) {
    await sleep(200);
    let done = false;
    try {
      const res = await fetch(`${envUrl}/done`);
      const payload = (await res.json()) as Record<string, unknown>;
      done = payload.done === true;
    } catch {
      done = false;
    }
    if (done) break;
  }
  server.close();
  process.exit(0);
}

void main();
