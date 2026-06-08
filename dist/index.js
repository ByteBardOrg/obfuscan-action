// src/index.ts
import { execFile } from "node:child_process";
import * as fs2 from "node:fs/promises";
import * as path3 from "node:path";
import { fileURLToPath as fileURLToPath3 } from "node:url";
import { promisify } from "node:util";

// ../core/dist/diff.js
var FILE_HEADER = /^diff --git a\/(.+?) b\/(.+?)$/;
var HUNK_HEADER = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/;
function parseDiffToFiles(diff) {
  if (!diff || diff.length === 0)
    return [];
  const out = [];
  const lines = diff.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    const line = lines[i] ?? "";
    const header = FILE_HEADER.exec(line);
    if (!header) {
      i++;
      continue;
    }
    let path4 = (header[2] ?? "").replace(/\\/g, "/");
    let status = "modified";
    const addedRanges = [];
    i++;
    while (i < lines.length) {
      const meta = lines[i] ?? "";
      if (FILE_HEADER.test(meta))
        break;
      if (meta.startsWith("@@"))
        break;
      if (meta.startsWith("new file mode"))
        status = "added";
      else if (meta.startsWith("deleted file mode"))
        status = "deleted";
      else if (meta.startsWith("--- ")) {
      } else if (meta.startsWith("+++ ")) {
        const rhs = meta.slice(4).trim();
        if (rhs === "/dev/null")
          status = "deleted";
        else if (rhs.startsWith("b/"))
          path4 = rhs.slice(2).replace(/\\/g, "/");
        else if (rhs !== "/dev/null")
          path4 = rhs.replace(/\\/g, "/");
      }
      i++;
    }
    while (i < lines.length) {
      const hunkLine = lines[i] ?? "";
      if (FILE_HEADER.test(hunkLine))
        break;
      if (!hunkLine.startsWith("@@")) {
        i++;
        continue;
      }
      const m = HUNK_HEADER.exec(hunkLine);
      if (!m) {
        i++;
        continue;
      }
      const hunk = {
        postStart: parseInt(m[1] ?? "0", 10) || 0
      };
      i++;
      let postCursor = hunk.postStart;
      let runStart = null;
      while (i < lines.length) {
        const body = lines[i] ?? "";
        if (FILE_HEADER.test(body) || body.startsWith("@@"))
          break;
        if (body.startsWith("+")) {
          if (runStart === null)
            runStart = postCursor;
          postCursor++;
          i++;
        } else if (body.startsWith(" ")) {
          if (runStart !== null) {
            addedRanges.push([runStart, postCursor - 1]);
            runStart = null;
          }
          postCursor++;
          i++;
        } else if (body.startsWith("-")) {
          if (runStart !== null) {
            addedRanges.push([runStart, postCursor - 1]);
            runStart = null;
          }
          i++;
        } else if (body.startsWith("\\")) {
          i++;
        } else if (body === "") {
          if (i + 1 >= lines.length) {
            i++;
            break;
          }
          if (runStart !== null) {
            addedRanges.push([runStart, postCursor - 1]);
            runStart = null;
          }
          postCursor++;
          i++;
        } else {
          break;
        }
      }
      if (runStart !== null)
        addedRanges.push([runStart, postCursor - 1]);
    }
    if (status !== "deleted") {
      out.push({ path: path4, status, addedRanges });
    }
  }
  return out;
}
function lineInRanges(line, ranges) {
  for (const [start, end] of ranges) {
    if (line >= start && line <= end)
      return true;
  }
  return false;
}

// ../core/dist/directives.js
var DIRECTIVE_RE = /obfuscan-disable-(next-line|line)\b\s*([A-Za-z0-9_.,\- *]*)/g;
function extractDisableDirectives(source) {
  const out = [];
  if (!source)
    return out;
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    DIRECTIVE_RE.lastIndex = 0;
    let m;
    while ((m = DIRECTIVE_RE.exec(line)) !== null) {
      const kind = m[1];
      const idsRaw = (m[2] ?? "").trim();
      const ruleIds = idsRaw.split(/[\s,]+/).map((s) => s.trim()).filter((s) => s.length > 0 && /^[A-Za-z0-9_.\-]+$/.test(s));
      const targetLine = kind === "next-line" ? i + 2 : i + 1;
      out.push({ line: targetLine, ruleIds });
    }
  }
  return out;
}
function isSuppressedByDirectives(line, ruleId, directives) {
  for (const d of directives) {
    if (d.line !== line)
      continue;
    if (d.ruleIds.length === 0)
      return true;
    if (d.ruleIds.some((id) => ruleId === id || ruleId.startsWith(id + "."))) {
      return true;
    }
  }
  return false;
}

// ../core/dist/allowlist.js
import { createHash } from "node:crypto";
var SEVERITY_RANK = { info: 0, warn: 1, block: 2 };
function hashSnippet(snippet) {
  const normalized = normalizeSnippet(snippet);
  return createHash("sha256").update(normalized, "utf8").digest("hex");
}
function normalizeSnippet(s) {
  return s.replace(/\s+/g, " ").trim();
}
function matchesAllowlist(finding, allowlist, filePath) {
  for (const entry of allowlist.paths ?? []) {
    if (!matchesPathEntry(filePath, entry))
      continue;
    if (entry.ruleId && !ruleMatches(finding.ruleId, entry.ruleId))
      continue;
    if (entry.maxSeverity) {
      if (SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[entry.maxSeverity]) {
        return true;
      }
    } else {
      return true;
    }
  }
  for (const entry of allowlist.snippets ?? []) {
    if (!ruleMatches(finding.ruleId, entry.ruleId))
      continue;
    if (hashSnippet(finding.snippet) === entry.snippetHash)
      return true;
  }
  return false;
}
function ruleMatches(ruleId, entryRuleId) {
  return ruleId === entryRuleId || ruleId.startsWith(entryRuleId + ".");
}
function matchesPathEntry(filePath, entry) {
  return globMatch(entry.pattern, filePath);
}
function globMatch(pattern, str) {
  const re = globToRegex(pattern);
  return re.test(str);
}
function globToRegex(pattern) {
  let out = "^";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        out += ".*";
        i++;
        if (pattern[i + 1] === "/") {
          i++;
        }
      } else {
        out += "[^/]*";
      }
    } else if (c === "?") {
      out += "[^/]";
    } else if (c === "[") {
      let j = i + 1;
      let cls = "[";
      while (j < pattern.length && pattern[j] !== "]") {
        cls += pattern[j];
        j++;
      }
      cls += "]";
      out += cls;
      i = j;
    } else if (c && /[.+^${}()|\\]/.test(c)) {
      out += "\\" + c;
    } else {
      out += c ?? "";
    }
  }
  out += "$";
  return new RegExp(out);
}

// ../core/dist/rules.js
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

// ../core/dist/errors.js
var InvalidScanInputError = class extends Error {
  name = "InvalidScanInputError";
};
var InvalidRuleSetError = class extends Error {
  details;
  name = "InvalidRuleSetError";
  constructor(message, details) {
    super(message);
    this.details = details;
  }
};

// ../core/dist/rules.js
async function loadRuleSet(opts) {
  const { languageDir } = opts;
  const entries = await fs.readdir(languageDir).catch((e) => {
    throw new InvalidRuleSetError(`failed to read language directory: ${languageDir}`, [{ file: languageDir, problem: String(e) }]);
  });
  const configs = /* @__PURE__ */ new Map();
  const aliasIndex = /* @__PURE__ */ new Map();
  const extIndex = /* @__PURE__ */ new Map();
  const filenameIndex = /* @__PURE__ */ new Map();
  const problems = [];
  for (const file of entries) {
    if (!file.endsWith(".json"))
      continue;
    if (file.startsWith("_"))
      continue;
    const full = path.join(languageDir, file);
    let raw;
    try {
      raw = await fs.readFile(full, "utf8");
    } catch (e) {
      problems.push({ file, problem: `read failed: ${String(e)}` });
      continue;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      problems.push({ file, problem: `invalid JSON: ${String(e)}` });
      continue;
    }
    const cfg = parsed;
    if (typeof cfg.id !== "string") {
      problems.push({ file, problem: "missing string field: id" });
      continue;
    }
    if (!Array.isArray(cfg.extensions)) {
      problems.push({ file, problem: "missing array field: extensions" });
      continue;
    }
    if (!Array.isArray(cfg.dynamic_exec_sinks)) {
      problems.push({ file, problem: "missing array field: dynamic_exec_sinks" });
      continue;
    }
    if (!Array.isArray(cfg.decoders)) {
      problems.push({ file, problem: "missing array field: decoders" });
      continue;
    }
    const config = cfg;
    configs.set(config.id, config);
    aliasIndex.set(config.id, config.id);
    for (const alias of config.aliases ?? []) {
      aliasIndex.set(alias, config.id);
    }
    for (const ext of config.extensions) {
      extIndex.set(ext.toLowerCase(), config.id);
    }
    for (const fname of config.filenames ?? []) {
      filenameIndex.set(fname, config.id);
    }
  }
  if (problems.length > 0 && configs.size === 0) {
    throw new InvalidRuleSetError(`no valid language configs in ${languageDir}`, problems);
  }
  return {
    languages: () => Array.from(configs.keys()).sort(),
    configFor: (id) => configs.get(aliasIndex.get(id) ?? id) ?? null,
    detectLanguage: (p) => detectLanguage(p, extIndex, filenameIndex),
    loadGrammar: async (id) => {
      return Object.freeze({ id, _internal: null });
    },
    version: () => "0.0.0-source"
    // placeholder; defaultRuleSet() supplies real CalVer
  };
}
function detectLanguage(filePath, extIndex, filenameIndex) {
  const norm = filePath.replace(/\\/g, "/");
  const base = norm.slice(norm.lastIndexOf("/") + 1);
  const exact = filenameIndex.get(base);
  if (exact)
    return exact;
  if (base === "package.json")
    return "json";
  if (base === "Dockerfile" || base.startsWith("Dockerfile."))
    return "dockerfile";
  if (norm.includes("/.github/workflows/") && (base.endsWith(".yml") || base.endsWith(".yaml"))) {
    return "yaml";
  }
  const lastDot = base.lastIndexOf(".");
  if (lastDot >= 0) {
    const ext = base.slice(lastDot).toLowerCase();
    const id = extIndex.get(ext);
    if (id)
      return id;
  }
  return null;
}
var RULES_VERSION_FALLBACK = "2026.04.0";
var here = path.dirname(fileURLToPath(import.meta.url));
var cachedDefault = null;
async function defaultRuleSet() {
  if (cachedDefault)
    return cachedDefault;
  const candidates = await locateBundledRules();
  for (const dir of candidates) {
    try {
      const rs = await loadRuleSet({ languageDir: dir });
      const version = await readPackageVersion(path.dirname(dir)) ?? RULES_VERSION_FALLBACK;
      cachedDefault = wrapWithVersion(rs, version);
      return cachedDefault;
    } catch {
    }
  }
  cachedDefault = emptyRuleSet();
  return cachedDefault;
}
async function locateBundledRules() {
  const candidates = [];
  candidates.push(path.resolve(here, "..", "..", "rules", "languages"));
  try {
    const req = (await import("node:module")).createRequire(import.meta.url);
    const pkgPath = req.resolve("@obfuscan/rules/package.json");
    candidates.push(path.join(path.dirname(pkgPath), "languages"));
  } catch {
  }
  const envDir = process.env["OBFUSCAN_RULES_DIR"];
  if (envDir)
    candidates.unshift(envDir);
  return candidates;
}
async function readPackageVersion(dir) {
  try {
    const raw = await fs.readFile(path.join(dir, "package.json"), "utf8");
    const pkg = JSON.parse(raw);
    return typeof pkg.version === "string" ? pkg.version : null;
  } catch {
    return null;
  }
}
function wrapWithVersion(rs, version) {
  return {
    languages: () => rs.languages(),
    configFor: (id) => rs.configFor(id),
    detectLanguage: (p) => rs.detectLanguage(p),
    loadGrammar: (id) => rs.loadGrammar(id),
    version: () => version
  };
}
function emptyRuleSet() {
  return {
    languages: () => [],
    configFor: () => null,
    detectLanguage: () => null,
    loadGrammar: async (id) => Object.freeze({ id, _internal: null }),
    version: () => RULES_VERSION_FALLBACK
  };
}

// ../core/dist/internal/text.js
var MAX_SNIPPET_LEN = 200;
var ELLIPSIS = "...";
function truncateSnippet(s) {
  if (s.length <= MAX_SNIPPET_LEN)
    return s;
  return s.slice(0, MAX_SNIPPET_LEN - ELLIPSIS.length) + ELLIPSIS;
}

// ../core/dist/detectors/high-entropy-literal.js
var STRING_LITERAL_RE = /(["'`])((?:\\.|(?!\1).){40,}?)\1/g;
var MIN_LEN = 40;
var ENTROPY_THRESHOLD = 4.5;
var MAX_SOURCE_BYTES = 2e6;
var MAX_FINDINGS_PER_FILE = 50;
var BASE64ISH_RE = /^[A-Za-z0-9+/=_-]+$/;
var DATA_URI_BASE64_RE = /^data:[^,]{1,120};base64,[A-Za-z0-9+/=]+$/i;
var ESCAPED_BYTES_RE = /^(?:\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\[0-7]{3})+$/;
function shannon(s) {
  if (s.length === 0)
    return 0;
  const freq = /* @__PURE__ */ new Map();
  for (const c of s)
    freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
function looksEncodedOrPacked(s) {
  if (DATA_URI_BASE64_RE.test(s))
    return true;
  if (ESCAPED_BYTES_RE.test(s))
    return true;
  if (/\s/.test(s))
    return false;
  return BASE64ISH_RE.test(s);
}
function lineAt(source, offset) {
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source.charCodeAt(i) === 10)
      line++;
  }
  return line;
}
var highEntropyLiteral = {
  id: "obf.high-entropy-literal",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfhigh-entropy-literal",
  applies(ctx) {
    return ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES;
  },
  run(ctx) {
    const findings = [];
    const src = ctx.source;
    let match;
    const re = new RegExp(STRING_LITERAL_RE.source, STRING_LITERAL_RE.flags);
    while ((match = re.exec(src)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_FILE)
        break;
      const body = match[2];
      if (!body || body.length < MIN_LEN)
        continue;
      if (!looksEncodedOrPacked(body))
        continue;
      const entropy = shannon(body);
      if (entropy < ENTROPY_THRESHOLD)
        continue;
      const line = lineAt(src, match.index);
      const score = Math.min(10, Math.round(entropy * 1.5));
      findings.push({
        ruleId: highEntropyLiteral.id,
        severity: "warn",
        score,
        file: ctx.path,
        line,
        snippet: truncateSnippet(body),
        reason: `High-entropy string literal (Shannon ${entropy.toFixed(2)} bits/char, length ${body.length}) \u2014 possible packed payload.`,
        evidence: {
          entropy: Number(entropy.toFixed(3)),
          length: body.length
        }
      });
    }
    return findings;
  }
};

// ../core/dist/internal/patterns.js
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
var UNSAFE_BARE_TAILS = /* @__PURE__ */ new Set([
  "call",
  "compile",
  "constructor",
  "decode",
  "do",
  "exec",
  "execute",
  "from",
  "get",
  "import",
  "invoke",
  "load",
  "new",
  "open",
  "parse",
  "post",
  "request",
  "require",
  "run",
  "send",
  "source",
  "spawn",
  "start",
  "system",
  "use"
]);
function isUnsafeBareTail(tail) {
  return UNSAFE_BARE_TAILS.has(tail.toLowerCase());
}
function qualifiedSuffix(raw) {
  const parts = raw.split(/(\.|::)/);
  const segments = parts.filter((_, i) => i % 2 === 0 && parts[i] !== "");
  const separators = parts.filter((_, i) => i % 2 === 1);
  if (segments.length < 2 || separators.length < 1)
    return null;
  const a = segments[segments.length - 2];
  const b = segments[segments.length - 1];
  const sep2 = separators[separators.length - 1];
  if (!a || !b || !sep2)
    return null;
  return `${a}${sep2}${b}`;
}
function namedCallAlternation(names, options = {}) {
  const alts = [];
  for (const raw of names) {
    if (!raw)
      continue;
    if (/^\[.+\]::/.test(raw)) {
      alts.push(escapeRegex(raw));
      continue;
    }
    if (/\s/.test(raw)) {
      alts.push(escapeRegex(raw));
      continue;
    }
    const parts = raw.split(/\.|::/);
    const tail = parts[parts.length - 1] ?? raw;
    alts.push(escapeRegex(raw));
    if (parts.length > 1 && tail !== raw && tail.length > 0) {
      if (isUnsafeBareTail(tail) && !options.allowUnsafeBareTails) {
        const suffix = qualifiedSuffix(raw);
        if (suffix && suffix !== raw)
          alts.push(escapeRegex(suffix));
        alts.push(`(?:\\.|::)${escapeRegex(tail)}`);
      } else {
        alts.push(escapeRegex(tail));
      }
    }
  }
  const seen = /* @__PURE__ */ new Set();
  const unique = [];
  for (const a of alts) {
    if (!seen.has(a)) {
      seen.add(a);
      unique.push(a);
    }
  }
  return unique.join("|");
}
function lineAtOffset(source, offset) {
  let line = 1;
  const cap = Math.min(offset, source.length);
  for (let i = 0; i < cap; i++) {
    if (source.charCodeAt(i) === 10)
      line++;
  }
  return line;
}
var MAX_FINDINGS_PER_DETECTOR = 50;
var MAX_SOURCE_BYTES2 = 2e6;

// ../core/dist/detectors/bidi-control.js
var BIDI_CHARS = [
  "\u202A",
  // LRE — Left-to-Right Embedding
  "\u202B",
  // RLE — Right-to-Left Embedding
  "\u202C",
  // PDF — Pop Directional Formatting
  "\u202D",
  // LRO — Left-to-Right Override
  "\u202E",
  // RLO — Right-to-Left Override
  "\u2066",
  // LRI — Left-to-Right Isolate
  "\u2067",
  // RLI — Right-to-Left Isolate
  "\u2068",
  // FSI — First Strong Isolate
  "\u2069"
  // PDI — Pop Directional Isolate
];
var BIDI_RE = new RegExp(`[${BIDI_CHARS.join("")}]`, "g");
var NAMES = {
  "\u202A": "LRE",
  "\u202B": "RLE",
  "\u202C": "PDF",
  "\u202D": "LRO",
  "\u202E": "RLO",
  "\u2066": "LRI",
  "\u2067": "RLI",
  "\u2068": "FSI",
  "\u2069": "PDI"
};
var bidiControlChar = {
  id: "obf.bidi-control",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfbidi-control",
  applies(ctx) {
    return ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES2;
  },
  run(ctx) {
    const findings = [];
    const src = ctx.source;
    let m;
    BIDI_RE.lastIndex = 0;
    while ((m = BIDI_RE.exec(src)) !== null) {
      const ch = m[0];
      const codePoint = ch.codePointAt(0);
      const line = lineAtOffset(src, m.index);
      const winStart = Math.max(0, m.index - 20);
      const winEnd = Math.min(src.length, m.index + 20);
      const snippet = src.slice(winStart, winEnd);
      findings.push({
        ruleId: bidiControlChar.id,
        severity: "block",
        score: 10,
        file: ctx.path,
        line,
        snippet: truncateSnippet(snippet),
        reason: `Unicode bidirectional control character ${NAMES[ch] ?? "?"} (U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}) found in source. This is a Trojan Source attack vector (CVE-2021-42574).`,
        evidence: { codePoint, name: NAMES[ch] ?? "unknown" }
      });
    }
    return findings;
  }
};

// ../core/dist/detectors/homoglyph-identifier.js
var IDENT_RE = /[A-Za-z_$][\p{L}\p{N}_$]{2,}/gu;
var CONFUSABLE_RE = /[\u0400-\u04FF\u0370-\u03FF]/;
var ASCII_LETTER_RE = /[A-Za-z]/;
var homoglyphIdentifier = {
  id: "obf.homoglyph-identifier",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfhomoglyph-identifier",
  applies(ctx) {
    return ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES2;
  },
  run(ctx) {
    const findings = [];
    const src = ctx.source;
    const seen = /* @__PURE__ */ new Set();
    const re = new RegExp(IDENT_RE.source, IDENT_RE.flags);
    let m;
    while ((m = re.exec(src)) !== null) {
      const ident = m[0];
      if (seen.has(ident))
        continue;
      if (!CONFUSABLE_RE.test(ident))
        continue;
      let ascii = 0;
      let confusable = 0;
      for (const c of ident) {
        if (ASCII_LETTER_RE.test(c))
          ascii++;
        else if (CONFUSABLE_RE.test(c))
          confusable++;
      }
      if (ascii === 0)
        continue;
      if (confusable === 0)
        continue;
      if (ascii < confusable)
        continue;
      seen.add(ident);
      const line = lineAtOffset(src, m.index);
      findings.push({
        ruleId: homoglyphIdentifier.id,
        severity: "block",
        score: 9,
        file: ctx.path,
        line,
        snippet: truncateSnippet(ident),
        reason: `Identifier mixes Latin letters with confusable characters from another script (Cyrillic/Greek). This is a homoglyph attack pattern.`,
        evidence: { identifier: ident, asciiCount: ascii, confusableCount: confusable }
      });
    }
    return findings;
  }
};

// ../core/dist/detectors/long-line.js
var LONG_LINE_THRESHOLD = 2e3;
var VERY_LONG_LINE_THRESHOLD = 1e4;
var longLine = {
  id: "obf.long-line",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obflong-line",
  applies(ctx) {
    return ctx.source.length > LONG_LINE_THRESHOLD && ctx.source.length < MAX_SOURCE_BYTES2;
  },
  run(ctx) {
    const findings = [];
    const src = ctx.source;
    let lineStart = 0;
    let lineNo = 1;
    const len = src.length;
    for (let i = 0; i <= len; i++) {
      if (i === len || src.charCodeAt(i) === 10) {
        const lineLen = i - lineStart;
        if (lineLen >= LONG_LINE_THRESHOLD) {
          const snippet = src.slice(lineStart, lineStart + 200);
          const score = lineLen >= VERY_LONG_LINE_THRESHOLD ? 8 : 5;
          const severity = lineLen >= VERY_LONG_LINE_THRESHOLD ? "warn" : "info";
          findings.push({
            ruleId: longLine.id,
            severity,
            score,
            file: ctx.path,
            line: lineNo,
            snippet: truncateSnippet(snippet),
            reason: `Line ${lineNo} is ${lineLen} characters long. This is the signature of minified or hand-obfuscated code. If the file is intentionally a bundle, suppress with a path allowlist entry.`,
            evidence: { lineLength: lineLen }
          });
        }
        lineStart = i + 1;
        lineNo++;
      }
    }
    return findings;
  }
};

// ../core/dist/detectors/encoded-array-fingerprint.js
var ARRAY_RE = /\[\s*((?:"[^"\n]{4,}"|'[^'\n]{4,}')(?:\s*,\s*(?:"[^"\n]{4,}"|'[^'\n]{4,}')){15,})\s*\]/g;
var MIN_BASE64_RATIO = 0.6;
var BASE64_CHAR = /[A-Za-z0-9+/=]/;
function looksBase64ish(s) {
  if (s.length < 8)
    return false;
  let hits = 0;
  for (const c of s)
    if (BASE64_CHAR.test(c))
      hits++;
  return hits / s.length >= MIN_BASE64_RATIO;
}
var encodedArrayFingerprint = {
  id: "obf.encoded-array-fingerprint",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfencoded-array-fingerprint",
  applies(ctx) {
    return ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES2;
  },
  run(ctx) {
    const findings = [];
    const src = ctx.source;
    const re = new RegExp(ARRAY_RE.source, ARRAY_RE.flags);
    let m;
    while ((m = re.exec(src)) !== null) {
      const elements = (m[1] ?? "").split(/,/).map((s) => s.trim().replace(/^["']|["']$/g, ""));
      const base64ish = elements.filter(looksBase64ish).length;
      if (base64ish / elements.length < MIN_BASE64_RATIO)
        continue;
      const line = lineAtOffset(src, m.index);
      findings.push({
        ruleId: encodedArrayFingerprint.id,
        severity: "warn",
        score: 7,
        file: ctx.path,
        line,
        snippet: truncateSnippet(m[0]),
        reason: `Large array of encoded-looking strings (${elements.length} entries, ${base64ish} base64-shaped). This is the obfuscator.io / javascript-obfuscator string-table fingerprint.`,
        evidence: { length: elements.length, base64ishCount: base64ish }
      });
    }
    return findings;
  }
};

// ../core/dist/detectors/decode-then-exec.js
var cache = /* @__PURE__ */ new WeakMap();
function candidateTokens(names) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const n of names) {
    if (!n)
      continue;
    const tail = n.split(/[.\/:\s]+/).filter(Boolean).pop() ?? n;
    const token = tail.replace(/[^A-Za-z0-9_]/g, "");
    if (token.length < 3)
      continue;
    if (seen.has(token))
      continue;
    seen.add(token);
    out.push(token);
  }
  return out;
}
function maybeRelevantSource(source, config) {
  const sinkTokens = candidateTokens(config.dynamic_exec_sinks);
  const decoderTokens = candidateTokens(config.decoders);
  const hasSink = sinkTokens.some((t) => source.includes(t));
  if (!hasSink)
    return false;
  return decoderTokens.some((t) => source.includes(t));
}
function compile(config) {
  const cached2 = cache.get(config);
  if (cached2)
    return cached2;
  const decoders = namedCallAlternation(config.decoders);
  const sinks = namedCallAlternation(config.dynamic_exec_sinks);
  const direct = new RegExp(`(?:${sinks})\\s*\\(([^()]{0,400}(?:\\([^()]*\\)[^()]{0,200}){0,3}(?:${decoders})\\s*\\()`, "g");
  const isShell = config.id === "bash" || (config.aliases ?? []).includes("sh");
  const bashSubshell = isShell ? new RegExp(`(?:${sinks})\\s+"?\\$\\([\\s\\S]{0,400}?(?:${decoders})(?:\\s|\\b)`, "g") : null;
  const directUnion = bashSubshell ? new RegExp(`${direct.source}|${bashSubshell.source}`, "g") : direct;
  const indirectAssign = new RegExp(`([A-Za-z_$][\\w$]*)\\s*(?:,\\s*[A-Za-z_$][\\w$]*)*\\s*(?::=|=)\\s*(?:await\\s+)?(?:${decoders})\\s*\\(`, "g");
  const sinkUse = (varName) => new RegExp(`(?:${sinks})\\s*(?:\\(|\\s+)\\s*(?:[A-Za-z_][\\w$]*\\s*\\(\\s*){0,2}[&*]*\\s*${escapeRegex(varName)}\\b`, "g");
  const sinkCall = new RegExp(`(?:${sinks})\\s*(?:\\(|\\s+)([\\s\\S]{0,24})`, "g");
  const decoderCall = new RegExp(`(?:${decoders})\\s*\\(`, "g");
  const compiled = {
    direct: directUnion,
    indirectAssign,
    sinkUse,
    sinkCall,
    decoderCall
  };
  cache.set(config, compiled);
  return compiled;
}
function isLiteralPeek(peek) {
  const trimmed = peek.replace(/^\s+/, "");
  if (trimmed.length === 0)
    return false;
  const c = trimmed[0];
  if (c === '"' || c === "'")
    return true;
  if (c >= "0" && c <= "9")
    return true;
  if (c === "-" && trimmed[1] && trimmed[1] >= "0" && trimmed[1] <= "9")
    return true;
  if (c === "`")
    return !trimmed.includes("${");
  return false;
}
var decodeThenExec = {
  id: "obf.decode-then-exec",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfdecode-then-exec",
  applies(ctx) {
    return ctx.config !== null && ctx.config.dynamic_exec_sinks.length > 0 && ctx.config.decoders.length > 0 && ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES2 && maybeRelevantSource(ctx.source, ctx.config);
  },
  run(ctx) {
    if (!ctx.config)
      return [];
    const cfg = ctx.config;
    const src = ctx.source;
    const { direct, indirectAssign, sinkUse, sinkCall, decoderCall } = compile(cfg);
    const findings = [];
    const seen = /* @__PURE__ */ new Set();
    let m;
    const directRe = new RegExp(direct.source, direct.flags);
    while ((m = directRe.exec(src)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR)
        break;
      const line = lineAtOffset(src, m.index);
      if (seen.has(line))
        continue;
      seen.add(line);
      findings.push(buildFinding(ctx, cfg.id, m[0], m.index, "direct"));
    }
    const assignRe = new RegExp(indirectAssign.source, indirectAssign.flags);
    while ((m = assignRe.exec(src)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR)
        break;
      const varName = m[1];
      if (!varName)
        continue;
      const after = src.slice(m.index + m[0].length);
      const useRe = sinkUse(varName);
      const useMatch = useRe.exec(after);
      if (!useMatch)
        continue;
      const useOffset = m.index + m[0].length + useMatch.index;
      const line = lineAtOffset(src, useOffset);
      if (seen.has(line))
        continue;
      seen.add(line);
      findings.push(buildFinding(ctx, cfg.id, useMatch[0], useOffset, "indirect"));
    }
    const hasDecoder = new RegExp(decoderCall.source, decoderCall.flags).test(src);
    if (hasDecoder) {
      const sinkRe = new RegExp(sinkCall.source, sinkCall.flags);
      while ((m = sinkRe.exec(src)) !== null) {
        if (findings.length >= MAX_FINDINGS_PER_DETECTOR)
          break;
        const peek = m[1] ?? "";
        if (isLiteralPeek(peek))
          continue;
        const offset = m.index + (m[0].length - peek.length);
        const line = lineAtOffset(src, offset);
        if (seen.has(line))
          continue;
        seen.add(line);
        findings.push(buildFinding(ctx, cfg.id, m[0], offset, "co-located"));
      }
    }
    return findings;
  }
};
function buildFinding(ctx, langId, rawSnippet, offset, flow) {
  const line = lineAtOffset(ctx.source, offset);
  return {
    ruleId: `obf.decode-then-exec.${langId}`,
    severity: "block",
    score: 9,
    file: ctx.path,
    line,
    snippet: truncateSnippet(rawSnippet),
    reason: `Decoded value flows into a dynamic-exec sink (${flow}). This is the canonical decode-then-exec obfuscation pattern.`,
    evidence: { language: langId, flow }
  };
}

// ../core/dist/detectors/dynamic-exec-non-literal.js
var cache2 = /* @__PURE__ */ new WeakMap();
function compile2(config) {
  const cached2 = cache2.get(config);
  if (cached2)
    return cached2;
  const sinks = namedCallAlternation(config.dynamic_exec_sinks);
  const call = new RegExp(`(?:^|[^A-Za-z0-9_$])((?:${sinks}))\\s*\\(([\\s\\S]{0,12})`, "g");
  const compiled = { call };
  cache2.set(config, compiled);
  return compiled;
}
function isLiteralPeek2(peek) {
  const trimmed = peek.replace(/^\s+/, "");
  if (trimmed.length === 0)
    return false;
  const c = trimmed[0];
  if (c === '"' || c === "'")
    return true;
  if (c >= "0" && c <= "9")
    return true;
  if (c === "-" && trimmed[1] && trimmed[1] >= "0" && trimmed[1] <= "9")
    return true;
  if (c === "`") {
    return !trimmed.includes("${");
  }
  return false;
}
var dynamicExecNonLiteral = {
  id: "obf.dynamic-exec-with-non-literal",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfdynamic-exec-with-non-literal",
  applies(ctx) {
    return ctx.config !== null && ctx.config.dynamic_exec_sinks.length > 0 && ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES2;
  },
  run(ctx) {
    if (!ctx.config)
      return [];
    const cfg = ctx.config;
    const src = ctx.source;
    const { call } = compile2(cfg);
    const findings = [];
    const seen = /* @__PURE__ */ new Set();
    const re = new RegExp(call.source, call.flags);
    let m;
    while ((m = re.exec(src)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR)
        break;
      const sinkName = m[1] ?? "";
      const peek = m[2] ?? "";
      if (isLiteralPeek2(peek))
        continue;
      if (/^[A-Za-z_$][\w$.]*\s*\(/.test(peek.replace(/^\s+/, ""))) {
        const fnNameMatch = /^([A-Za-z_$][\w$.]*)/.exec(peek.replace(/^\s+/, ""));
        const fnName = fnNameMatch?.[1] ?? "";
        if (cfg.decoders.some((d) => fnName === d || fnName.endsWith("." + d)))
          continue;
      }
      const offset = m.index + (m[0].length - peek.length);
      const line = lineAtOffset(src, offset);
      if (seen.has(line))
        continue;
      seen.add(line);
      findings.push({
        ruleId: `obf.dynamic-exec-with-non-literal.${cfg.id}`,
        severity: "warn",
        score: 7,
        file: ctx.path,
        line,
        snippet: truncateSnippet(`${sinkName}(${peek}`),
        reason: `Dynamic-exec sink \`${sinkName}\` called with a non-literal argument. Confirm the input cannot be attacker-influenced.`,
        evidence: { language: cfg.id, sink: sinkName }
      });
    }
    return findings;
  }
};

// ../core/dist/detectors/network-then-exec.js
var cache3 = /* @__PURE__ */ new WeakMap();
function candidateTokens2(names) {
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const n of names) {
    if (!n)
      continue;
    const tail = n.split(/[.\/:\s]+/).filter(Boolean).pop() ?? n;
    const token = tail.replace(/[^A-Za-z0-9_]/g, "");
    if (token.length < 3)
      continue;
    if (seen.has(token))
      continue;
    seen.add(token);
    out.push(token);
  }
  return out;
}
function maybeRelevantSource2(source, config) {
  const networkTokens = candidateTokens2(config.network_io ?? []);
  const sinkTokens = candidateTokens2(config.dynamic_exec_sinks);
  const hasNetwork = networkTokens.some((t) => source.includes(t));
  if (!hasNetwork)
    return false;
  return sinkTokens.some((t) => source.includes(t));
}
function compile3(config) {
  const cached2 = cache3.get(config);
  if (cached2)
    return cached2;
  const network = namedCallAlternation(config.network_io ?? []);
  const sinks = namedCallAlternation(config.dynamic_exec_sinks);
  const direct = new RegExp(`(?:${sinks})\\s*[("\\s][\\s\\S]{0,400}?(?:${network})\\s*[("\\s]`, "g");
  const bashSubshell = new RegExp(`(?:${sinks})\\s+"?\\$\\([\\s\\S]{0,400}?(?:${network})\\b`, "g");
  const isShell = config.id === "bash" || config.aliases?.includes("sh");
  const directUnion = isShell ? new RegExp(`${direct.source}|${bashSubshell.source}`, "g") : direct;
  const indirectAssign = new RegExp(`(?:(?:const|let|var|my|local|\\$)\\s+)?([A-Za-z_$][\\w$]*)\\s*[:=]\\s*(?:await\\s+)?(?:${network})\\s*\\(`, "g");
  const sinkUse = (v) => new RegExp(`(?:${sinks})\\s*[("\\s][^()]{0,200}\\b${escapeRegex(v)}\\b`, "g");
  const compiled = { direct: directUnion, indirectAssign, sinkUse };
  cache3.set(config, compiled);
  return compiled;
}
var networkThenExec = {
  id: "obf.network-then-exec",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfnetwork-then-exec",
  applies(ctx) {
    return ctx.config !== null && (ctx.config.network_io?.length ?? 0) > 0 && ctx.config.dynamic_exec_sinks.length > 0 && ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES2 && maybeRelevantSource2(ctx.source, ctx.config);
  },
  run(ctx) {
    if (!ctx.config)
      return [];
    const cfg = ctx.config;
    const src = ctx.source;
    const { direct, indirectAssign, sinkUse } = compile3(cfg);
    const findings = [];
    const seen = /* @__PURE__ */ new Set();
    let m;
    const directRe = new RegExp(direct.source, direct.flags);
    while ((m = directRe.exec(src)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR)
        break;
      const line = lineAtOffset(src, m.index);
      if (seen.has(line))
        continue;
      seen.add(line);
      findings.push(make(ctx, cfg.id, m[0], m.index, "direct"));
    }
    const assignRe = new RegExp(indirectAssign.source, indirectAssign.flags);
    while ((m = assignRe.exec(src)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR)
        break;
      const v = m[1];
      if (!v)
        continue;
      const after = src.slice(m.index + m[0].length);
      const u = sinkUse(v).exec(after);
      if (!u)
        continue;
      const offset = m.index + m[0].length + u.index;
      const line = lineAtOffset(src, offset);
      if (seen.has(line))
        continue;
      seen.add(line);
      findings.push(make(ctx, cfg.id, u[0], offset, "indirect"));
    }
    return findings;
  }
};
function make(ctx, langId, rawSnippet, offset, flow) {
  return {
    ruleId: `obf.network-then-exec.${langId}`,
    severity: "block",
    score: 10,
    file: ctx.path,
    line: lineAtOffset(ctx.source, offset),
    snippet: truncateSnippet(rawSnippet),
    reason: `Network IO result flows into a dynamic-exec sink (${flow}). The executed code is fully attacker-controlled.`,
    evidence: { language: langId, flow }
  };
}

// ../core/dist/detectors/deserializer-untrusted.js
var SAFE_DESERIALIZERS = /* @__PURE__ */ new Set([
  "JSON.parse",
  "v8.deserialize",
  "node:v8.deserialize",
  "json_decode"
]);
var cache4 = /* @__PURE__ */ new WeakMap();
function compile4(config) {
  const cached2 = cache4.get(config);
  if (cached2)
    return cached2;
  const list = (config.deserializers ?? []).filter((d) => !SAFE_DESERIALIZERS.has(d));
  if (list.length === 0)
    return null;
  const alt = namedCallAlternation(list);
  const re = new RegExp(`(?:^|[^A-Za-z0-9_$])((?:${alt}))\\s*\\(([\\s\\S]{0,16})`, "g");
  cache4.set(config, re);
  return re;
}
var DEFINITION_PREFIX_RE = /(?:\b(?:def|function|fn|func|sub)\s+|class\s+)$/;
function looksLikeLiteralCall(peek) {
  const t = peek.replace(/^\s+/, "");
  if (t.length === 0)
    return false;
  const c = t[0];
  return c === '"' || c === "'" || c >= "0" && c <= "9";
}
var deserializerUntrusted = {
  id: "obf.deserializer-untrusted",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfdeserializer-untrusted",
  applies(ctx) {
    return ctx.config !== null && (ctx.config.deserializers?.length ?? 0) > 0 && ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES2;
  },
  run(ctx) {
    if (!ctx.config)
      return [];
    const cfg = ctx.config;
    const re = compile4(cfg);
    if (!re)
      return [];
    const findings = [];
    const local = new RegExp(re.source, re.flags);
    let m;
    while ((m = local.exec(ctx.source)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR)
        break;
      const name = m[1] ?? "";
      const peek = m[2] ?? "";
      if (looksLikeLiteralCall(peek))
        continue;
      const lookback = ctx.source.slice(Math.max(0, m.index - 20), m.index + 1);
      if (DEFINITION_PREFIX_RE.test(lookback))
        continue;
      const offset = m.index + (m[0].length - peek.length);
      findings.push({
        ruleId: `obf.deserializer-untrusted.${cfg.id}`,
        severity: "block",
        score: 9,
        file: ctx.path,
        line: lineAtOffset(ctx.source, offset),
        snippet: truncateSnippet(`${name}(${peek}`),
        reason: `Unsafe deserializer \`${name}\` called with a non-literal argument. Untrusted input here is RCE.`,
        evidence: { language: cfg.id, deserializer: name }
      });
    }
    return findings;
  }
};

// ../core/dist/detectors/suspicious-io-cluster.js
var SECRET_PATH_RE = /(\.npmrc|\.aws[\/\\]credentials|\.aws[\/\\]config|\.ssh[\/\\]id_[a-z0-9_]+|\.docker[\/\\]config|\.gitconfig|\.netrc|GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY)/g;
var cache5 = /* @__PURE__ */ new WeakMap();
function compile5(config) {
  const cached2 = cache5.get(config);
  if (cached2)
    return cached2;
  const net = config.network_io ?? [];
  const sec = config.secrets_io ?? [];
  const shell = config.shell_exec ?? [];
  const compiled = {
    network: net.length ? new RegExp(`(?:${namedCallAlternation(net)})\\s*\\(`, "g") : null,
    secretsIo: sec.length ? new RegExp(`(?:${namedCallAlternation(sec)})\\s*\\(`, "g") : null,
    shellExec: shell.length ? new RegExp(`(?:${namedCallAlternation(shell)})\\s*\\(`, "g") : null
  };
  cache5.set(config, compiled);
  return compiled;
}
var suspiciousIoCluster = {
  id: "obf.suspicious-io-cluster",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfsuspicious-io-cluster",
  applies(ctx) {
    return ctx.config !== null && ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES2;
  },
  run(ctx) {
    if (!ctx.config)
      return [];
    const cfg = ctx.config;
    const src = ctx.source;
    const { network, shellExec } = compile5(cfg);
    if (!network)
      return [];
    const secretPathMatch = SECRET_PATH_RE.exec(src);
    SECRET_PATH_RE.lastIndex = 0;
    const hasSecretPath = !!secretPathMatch;
    const netRe = new RegExp(network.source, network.flags);
    const netMatch = netRe.exec(src);
    if (!netMatch)
      return [];
    const shellMatch = shellExec ? new RegExp(shellExec.source, shellExec.flags).exec(src) : null;
    if (!hasSecretPath && !shellMatch)
      return [];
    const findings = [];
    if (findings.length >= MAX_FINDINGS_PER_DETECTOR)
      return findings;
    const offset = hasSecretPath ? Math.min(secretPathMatch.index, netMatch.index) : Math.min(shellMatch.index, netMatch.index);
    findings.push({
      ruleId: `obf.suspicious-io-cluster.${cfg.id}`,
      severity: "warn",
      score: 8,
      file: ctx.path,
      line: lineAtOffset(src, offset),
      snippet: truncateSnippet(src.slice(offset, Math.min(src.length, offset + 200))),
      reason: `File reads from a known secrets location AND makes a network call. This is the data-exfil cluster shape that defines supply-chain malware.`,
      evidence: {
        language: cfg.id,
        secretMarker: secretPathMatch?.[0] ?? null,
        shellCall: shellMatch?.[0] ?? null,
        networkCall: netMatch[0]
      }
    });
    return findings;
  }
};

// ../core/dist/detectors/string-array-decoder.js
var ARRAY_RE2 = /\[\s*((?:"[^"\n]{4,}"|'[^'\n]{4,}')(?:\s*,\s*(?:"[^"\n]{4,}"|'[^'\n]{4,}')){15,})\s*\]/g;
var cache6 = /* @__PURE__ */ new WeakMap();
function compile6(config) {
  const cached2 = cache6.get(config);
  if (cached2)
    return cached2;
  const compiled = {
    decoder: new RegExp(`(?:${namedCallAlternation(config.decoders)})\\s*\\(`, "g"),
    sink: new RegExp(`(?:${namedCallAlternation(config.dynamic_exec_sinks)})\\s*\\(`, "g")
  };
  cache6.set(config, compiled);
  return compiled;
}
var stringArrayDecoder = {
  id: "obf.string-array-decoder",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfstring-array-decoder",
  applies(ctx) {
    return ctx.config !== null && ctx.config.decoders.length > 0 && ctx.config.dynamic_exec_sinks.length > 0 && ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES2;
  },
  run(ctx) {
    if (!ctx.config)
      return [];
    const src = ctx.source;
    const { decoder, sink } = compile6(ctx.config);
    const arrRe = new RegExp(ARRAY_RE2.source, ARRAY_RE2.flags);
    const arrayMatch = arrRe.exec(src);
    if (!arrayMatch)
      return [];
    const decRe = new RegExp(decoder.source, decoder.flags);
    if (!decRe.exec(src))
      return [];
    const sinkRe = new RegExp(sink.source, sink.flags);
    if (!sinkRe.exec(src))
      return [];
    const findings = [];
    if (findings.length >= MAX_FINDINGS_PER_DETECTOR)
      return findings;
    findings.push({
      ruleId: `obf.string-array-decoder.${ctx.config.id}`,
      severity: "block",
      score: 9,
      file: ctx.path,
      line: lineAtOffset(src, arrayMatch.index),
      snippet: truncateSnippet(arrayMatch[0]),
      reason: `String-array + decoder + dynamic-exec sink present in the same file. This is the obfuscator.io / javascript-obfuscator structural fingerprint.`,
      evidence: { language: ctx.config.id }
    });
    return findings;
  }
};

// ../core/dist/detectors/shell-untrusted-input.js
var DYNAMIC_ARG_RE = /(\$\{[^}]+\}|`[^`]*\$\{|f["'][^"']*\{[^}]+\}|"[^"]*%[sdif]"|\+\s*[A-Za-z_$][\w$]*|\$[A-Za-z_]\w*)/;
var cache7 = /* @__PURE__ */ new WeakMap();
function compile7(config) {
  if (cache7.has(config))
    return cache7.get(config) ?? null;
  const list = config.shell_exec ?? [];
  if (list.length === 0) {
    cache7.set(config, null);
    return null;
  }
  const alt = namedCallAlternation(list, { allowUnsafeBareTails: true });
  const re = new RegExp(`(?:^|[^A-Za-z0-9_$])((?:${alt}))\\s*\\(([^)\\n]{0,200})`, "g");
  cache7.set(config, re);
  return re;
}
var shellUntrustedInput = {
  id: "obf.shell-with-untrusted-input",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfshell-with-untrusted-input",
  applies(ctx) {
    return ctx.config !== null && (ctx.config.shell_exec?.length ?? 0) > 0 && ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES2;
  },
  run(ctx) {
    if (!ctx.config)
      return [];
    const cfg = ctx.config;
    const re = compile7(cfg);
    if (!re)
      return [];
    const findings = [];
    const local = new RegExp(re.source, re.flags);
    let m;
    while ((m = local.exec(ctx.source)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR)
        break;
      const name = m[1] ?? "";
      const args = m[2] ?? "";
      if (!DYNAMIC_ARG_RE.test(args))
        continue;
      const offset = m.index + (m[0].length - args.length);
      findings.push({
        ruleId: `obf.shell-with-untrusted-input.${cfg.id}`,
        severity: "warn",
        score: 7,
        file: ctx.path,
        line: lineAtOffset(ctx.source, offset),
        snippet: truncateSnippet(`${name}(${args}`),
        reason: `Shell-exec sink \`${name}\` called with an interpolated/concatenated argument. Confirm any user input is escaped or routed through an arg-array form.`,
        evidence: { language: cfg.id, sink: name }
      });
    }
    return findings;
  }
};

// ../core/dist/detectors/library-load-non-literal.js
var cache8 = /* @__PURE__ */ new WeakMap();
function compile8(config) {
  if (cache8.has(config))
    return cache8.get(config) ?? null;
  const list = config.library_load ?? [];
  if (list.length === 0) {
    cache8.set(config, null);
    return null;
  }
  const re = new RegExp(`(?:^|[^A-Za-z0-9_$])((?:${namedCallAlternation(list)}))\\s*\\(([\\s\\S]{0,12})`, "g");
  cache8.set(config, re);
  return re;
}
function looksLikeLiteral(peek) {
  const t = peek.replace(/^\s+/, "");
  if (t.length === 0)
    return false;
  const c = t[0];
  return c === '"' || c === "'" || c === "`" && !t.includes("${");
}
var libraryLoadNonLiteral = {
  id: "obf.library-load-non-literal",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obflibrary-load-non-literal",
  applies(ctx) {
    return ctx.config !== null && (ctx.config.library_load?.length ?? 0) > 0 && ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES2;
  },
  run(ctx) {
    if (!ctx.config)
      return [];
    const cfg = ctx.config;
    const re = compile8(cfg);
    if (!re)
      return [];
    const findings = [];
    const local = new RegExp(re.source, re.flags);
    let m;
    while ((m = local.exec(ctx.source)) !== null) {
      if (findings.length >= MAX_FINDINGS_PER_DETECTOR)
        break;
      const name = m[1] ?? "";
      const peek = m[2] ?? "";
      if (looksLikeLiteral(peek))
        continue;
      const offset = m.index + (m[0].length - peek.length);
      findings.push({
        ruleId: `obf.library-load-non-literal.${cfg.id}`,
        severity: "warn",
        score: 7,
        file: ctx.path,
        line: lineAtOffset(ctx.source, offset),
        snippet: truncateSnippet(`${name}(${peek}`),
        reason: `Dynamic library load \`${name}\` called with a non-literal argument. Module name flowing from a variable is suspicious.`,
        evidence: { language: cfg.id, loader: name }
      });
    }
    return findings;
  }
};

// ../core/dist/detectors/npm-c2-dropper.js
var JS_LIKE = /* @__PURE__ */ new Set(["javascript", "typescript"]);
var C2_RE = /(?:slack\.com|conversations\.history|auth\.test|\bAuthorization\s*:\s*["']Bearer\s+|\bxox[abprs]-)/;
var CRYPTO_RE = /(?:AES-GCM|PBKDF2|subtle|\.decrypt\s*\(|deriveKey\s*\(|importKey\s*\()/;
var WRITE_RE = /\bwriteFileSync\s*\(/;
var CHMOD_RE = /\bchmodSync\s*\(/;
var CHILD_PROCESS_RE = /(?:\bspawn\s*[:=,}]|\bexecSync\s*[:=,}]|\bchild_process\b|\bprocess\.execPath\b|\b\.unref\s*\()/;
var SELF_DELETE_RE = /\bunlinkSync\s*\(\s*__filename\b/;
var npmC2Dropper = {
  id: "obf.npm-c2-dropper",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfnpm-c2-dropper",
  applies(ctx) {
    return ctx.source.length > 0 && ctx.source.length < MAX_SOURCE_BYTES2 && (ctx.languageId === null || JS_LIKE.has(ctx.languageId));
  },
  run(ctx) {
    const src = ctx.source;
    const c2 = C2_RE.exec(src);
    if (!c2)
      return [];
    const crypto = CRYPTO_RE.exec(src);
    if (!crypto)
      return [];
    const write = WRITE_RE.exec(src);
    const chmod = CHMOD_RE.exec(src);
    const child = CHILD_PROCESS_RE.exec(src);
    const selfDelete = SELF_DELETE_RE.exec(src);
    if (!write || !chmod || !child)
      return [];
    const offset = Math.min(c2.index, crypto.index, write.index, chmod.index, child.index, selfDelete?.index ?? Number.POSITIVE_INFINITY);
    return [{
      ruleId: npmC2Dropper.id,
      severity: "block",
      score: 10,
      file: ctx.path,
      line: lineAtOffset(src, offset),
      snippet: truncateSnippet(src.slice(offset, offset + 200)),
      reason: `JavaScript package contains C2 polling, decrypt-stage, write/chmod, and child-process launch signals. This matches npm command-and-control dropper behavior.`,
      evidence: {
        c2: c2[0],
        crypto: crypto[0],
        writesFile: true,
        chmodsFile: true,
        launchesChildProcess: true,
        selfDelete: !!selfDelete
      }
    }];
  }
};

// ../core/dist/detectors/manifest-install-script.js
function classify(p) {
  const norm = p.replace(/\\/g, "/");
  const base = norm.slice(norm.lastIndexOf("/") + 1);
  if (base === "package.json")
    return "npm";
  if (base === "composer.json")
    return "composer";
  if (base.endsWith(".gemspec"))
    return "gemspec";
  if (base.endsWith(".rockspec"))
    return "rockspec";
  if (base.endsWith(".nuspec"))
    return "nuspec";
  return null;
}
var CURL_PIPE_SHELL_RE = /(?:curl|wget|fetch|Invoke-WebRequest|iwr)\b[^\n]{0,300}\|\s*(?:bash|sh|zsh|python|node|perl|powershell|pwsh|iex|Invoke-Expression)/i;
var PS_IEX_DOWNLOAD_RE = /\b(?:iex|Invoke-Expression)\b[^\n]{0,300}\b(?:DownloadString|DownloadFile|Invoke-WebRequest|wget|curl)\b/i;
function isCurlPipeShape(s) {
  return CURL_PIPE_SHELL_RE.test(s) || PS_IEX_DOWNLOAD_RE.test(s);
}
var NPM_INSTALL_HOOKS = ["preinstall", "install", "postinstall", "prepare"];
function scanNpm(ctx, pkg) {
  if (!pkg.scripts || typeof pkg.scripts !== "object")
    return [];
  const findings = [];
  for (const hook of NPM_INSTALL_HOOKS) {
    const cmd = pkg.scripts[hook];
    if (typeof cmd !== "string" || cmd.length === 0)
      continue;
    findings.push(buildFinding2(ctx, "npm", hook, cmd, lineOfJsonKey(ctx.source, hook)));
  }
  return findings;
}
var COMPOSER_INSTALL_HOOKS = [
  "pre-install-cmd",
  "post-install-cmd",
  "pre-update-cmd",
  "post-update-cmd",
  "post-autoload-dump"
];
function scanComposer(ctx, pkg) {
  if (!pkg.scripts || typeof pkg.scripts !== "object")
    return [];
  const findings = [];
  for (const hook of COMPOSER_INSTALL_HOOKS) {
    const raw = pkg.scripts[hook];
    if (raw == null)
      continue;
    const cmds = Array.isArray(raw) ? raw : [raw];
    for (const cmd of cmds) {
      if (typeof cmd !== "string" || cmd.length === 0)
        continue;
      findings.push(buildFinding2(ctx, "composer", hook, cmd, lineOfJsonKey(ctx.source, hook)));
    }
  }
  return findings;
}
var GEMSPEC_EXTENSIONS_RE = /\b\w+\.extensions\s*(?:=|<<)\s*(\[[^\]]*\]|%w[\[\(][^\]\)]*[\]\)]|['"][^'"]+['"])/;
function scanGemspec(ctx) {
  const m = GEMSPEC_EXTENSIONS_RE.exec(ctx.source);
  if (!m)
    return [];
  const value = m[1] ?? "";
  return [buildFinding2(ctx, "gemspec", "extensions", value, lineAt2(ctx.source, m.index))];
}
var ROCKSPEC_BUILD_TYPE_RE = /build\s*=\s*\{[^}]*?type\s*=\s*['"]command['"]/s;
var ROCKSPEC_COMMAND_FIELD_RE = /(\bbuild_command\b|\binstall_command\b|\bcommand\b)\s*=\s*['"]([^'"\n]{1,400})['"]/;
function scanRockspec(ctx) {
  const findings = [];
  const declaresCommand = ROCKSPEC_BUILD_TYPE_RE.test(ctx.source);
  const cmd = ROCKSPEC_COMMAND_FIELD_RE.exec(ctx.source);
  if (declaresCommand) {
    const where = ctx.source.search(ROCKSPEC_BUILD_TYPE_RE);
    findings.push(buildFinding2(ctx, "rockspec", "build.type", "command", where >= 0 ? lineAt2(ctx.source, where) : 1));
  }
  if (cmd) {
    const field = cmd[1] ?? "command";
    const value = cmd[2] ?? "";
    findings.push(buildFinding2(ctx, "rockspec", field, value, lineAt2(ctx.source, cmd.index)));
  }
  return findings;
}
var NUSPEC_FILES_PS1_RE = /<files?\b[^>]*\bsrc\s*=\s*['"]([^'"]*\b(?:install|init|uninstall)\.ps1)['"]/gi;
function scanNuspec(ctx) {
  const findings = [];
  let m;
  NUSPEC_FILES_PS1_RE.lastIndex = 0;
  while ((m = NUSPEC_FILES_PS1_RE.exec(ctx.source)) !== null) {
    const ref = m[1] ?? "";
    findings.push(buildFinding2(ctx, "nuspec", "files.install-ps1", ref, lineAt2(ctx.source, m.index)));
  }
  return findings;
}
function buildFinding2(ctx, manifest, hook, command, line) {
  const escalated = isCurlPipeShape(command);
  return {
    ruleId: "obf.manifest-install-script",
    severity: escalated ? "block" : "warn",
    score: escalated ? 9 : 6,
    file: ctx.path,
    line,
    snippet: truncateSnippet(`${manifest}:${hook} ${command}`),
    reason: escalated ? reasonEscalated(manifest, hook) : reasonBase(manifest, hook),
    evidence: { manifest, hook, command, curlPipeShell: escalated }
  };
}
function reasonBase(manifest, hook) {
  switch (manifest) {
    case "npm":
      return `npm \`${hook}\` lifecycle script runs automatically on \`npm install\`. Review for network calls, decoders, or shell-exec patterns.`;
    case "composer":
      return `Composer \`${hook}\` script runs during \`composer install\`/\`update\`. Review for network calls, decoders, or shell-exec patterns.`;
    case "gemspec":
      return `Gemspec declares native extensions; \`gem install\` will execute the referenced \`extconf.rb\` / \`Rakefile\` on the user's machine.`;
    case "rockspec":
      return `Rockspec declares a \`${hook}\` build hook; \`luarocks install\` will run this command on the user's machine.`;
    case "nuspec":
      return `.nuspec ships an auto-run PowerShell file (\`${hook}\`); legacy NuGet clients execute these on package install.`;
  }
}
function reasonEscalated(manifest, hook) {
  return `${manifest} \`${hook}\` hook pipes a network download into a shell. This is the exfil/payload-delivery shape behind the axios-2026 / chalk+debug-2025 supply-chain incidents.`;
}
function lineOfJsonKey(source, key) {
  const re = new RegExp(`"${key.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&")}"\\s*:`, "g");
  const m = re.exec(source);
  if (!m)
    return 1;
  return lineAt2(source, m.index);
}
function lineAt2(source, offset) {
  let line = 1;
  const stop = Math.min(offset, source.length);
  for (let i = 0; i < stop; i++) {
    if (source.charCodeAt(i) === 10)
      line++;
  }
  return line;
}
var manifestInstallScript = {
  id: "obf.manifest-install-script",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfmanifest-install-script",
  applies(ctx) {
    return classify(ctx.path) !== null;
  },
  run(ctx) {
    const kind = classify(ctx.path);
    if (kind === null)
      return [];
    switch (kind) {
      case "npm": {
        let pkg;
        try {
          pkg = JSON.parse(ctx.source);
        } catch {
          return [];
        }
        return scanNpm(ctx, pkg);
      }
      case "composer": {
        let pkg;
        try {
          pkg = JSON.parse(ctx.source);
        } catch {
          return [];
        }
        return scanComposer(ctx, pkg);
      }
      case "gemspec":
        return scanGemspec(ctx);
      case "rockspec":
        return scanRockspec(ctx);
      case "nuspec":
        return scanNuspec(ctx);
    }
  }
};

// ../core/dist/detectors/python-setup-side-effect.js
function isSetupPy(p) {
  return p === "setup.py" || p.endsWith("/setup.py");
}
var ALLOWED_LINE_RE = /^(?:\s*$|\s*#|from\s+\S+\s+import\s+|import\s+\S+|setup\s*\(|\)\s*$|\s*[\w]+\s*=\s*[^=].*$)/;
var SUSPICIOUS_RE = /(urllib\.request|requests\.|httpx\.|urlretrieve|os\.system|subprocess\.|Popen|socket\.|exec\s*\(|eval\s*\(|base64\.b64decode\s*\()/;
var pythonSetupSideEffect = {
  id: "obf.python-setup-side-effect",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfpython-setup-side-effect",
  applies(ctx) {
    return isSetupPy(ctx.path);
  },
  run(ctx) {
    const findings = [];
    const lines = ctx.source.split("\n");
    let inSetupCall = false;
    let parenDepth = 0;
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i] ?? "";
      const line = raw;
      if (inSetupCall) {
        for (const c of line) {
          if (c === "(")
            parenDepth++;
          else if (c === ")") {
            parenDepth--;
            if (parenDepth <= 0) {
              inSetupCall = false;
              parenDepth = 0;
              break;
            }
          }
        }
        continue;
      }
      if (/^\s*setup\s*\(/.test(line)) {
        inSetupCall = true;
        parenDepth = 0;
        for (const c of line) {
          if (c === "(")
            parenDepth++;
          else if (c === ")")
            parenDepth--;
        }
        if (parenDepth <= 0)
          inSetupCall = false;
        continue;
      }
      if (/^\s/.test(line))
        continue;
      if (SUSPICIOUS_RE.test(line)) {
        findings.push({
          ruleId: pythonSetupSideEffect.id,
          severity: "block",
          score: 9,
          file: ctx.path,
          line: i + 1,
          snippet: truncateSnippet(line.trim()),
          reason: `setup.py contains code outside the \`setup()\` call that performs network, shell, or eval-like side effects at install time. This is the canonical \`pip install\` malware shape.`,
          evidence: {}
        });
        break;
      }
      if (!ALLOWED_LINE_RE.test(line) && /\(/.test(line)) {
      }
    }
    return findings;
  }
};

// ../core/dist/detectors/perl-makefile-side-effect.js
function isPerlInstaller(p) {
  const norm = p.replace(/\\/g, "/");
  const base = norm.slice(norm.lastIndexOf("/") + 1);
  return base === "Makefile.PL" || base === "Build.PL";
}
var SUSPICIOUS_RE2 = /(\bsystem\s*\(|\bexec\s*\(|`[^`]*`|qx[\s({\[]|LWP::|HTTP::Tiny|IO::Socket|Net::|MIME::Base64|decode_base64|\beval\s*\{|\beval\s*['"]|use\s+inline\b)/i;
var perlMakefileSideEffect = {
  id: "obf.perl-makefile-side-effect",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfperl-makefile-side-effect",
  applies(ctx) {
    return isPerlInstaller(ctx.path);
  },
  run(ctx) {
    const findings = [];
    const lines = ctx.source.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i] ?? "";
      const code = raw.replace(/(?<!\\)#.*$/, "");
      if (code.trim().length === 0)
        continue;
      if (/^\s/.test(raw))
        continue;
      if (/^\s*(?:use|no|require|package|our|my)\b/.test(code) || /^\s*(?:WriteMakefile|Module::Build)\b/.test(code) || /^\s*\)/.test(code)) {
        continue;
      }
      if (SUSPICIOUS_RE2.test(code)) {
        findings.push({
          ruleId: perlMakefileSideEffect.id,
          severity: "block",
          score: 9,
          file: ctx.path,
          line: i + 1,
          snippet: truncateSnippet(code.trim()),
          reason: `${ctx.path} contains code outside the declarative \`WriteMakefile\` / \`Module::Build\` call that performs network, shell, or eval-like side effects. CPAN clients execute this file on the user's machine during \`cpan install\`.`,
          evidence: {}
        });
        break;
      }
    }
    return findings;
  }
};

// ../core/dist/detectors/cargo-build-rs-network.js
function isBuildRs(p) {
  return p === "build.rs" || p.endsWith("/build.rs");
}
var NETWORK_RE = /\b(?:reqwest::|ureq::|isahc::|hyper::|surf::|attohttpc::|curl::|tokio::net|std::net::TcpStream|std::net::UdpSocket)/g;
var PROCESS_NETWORK_RE = /Command::new\s*\(\s*"(?:curl|wget|powershell|pwsh)"/g;
var cargoBuildRsNetwork = {
  id: "obf.cargo-build-rs-network",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfcargo-build-rs-network",
  applies(ctx) {
    return isBuildRs(ctx.path);
  },
  run(ctx) {
    const findings = [];
    const src = ctx.source;
    const seen = /* @__PURE__ */ new Set();
    for (const re of [NETWORK_RE, PROCESS_NETWORK_RE]) {
      const local = new RegExp(re.source, re.flags);
      let m;
      while ((m = local.exec(src)) !== null) {
        const line = lineAtOffset(src, m.index);
        if (seen.has(line))
          continue;
        seen.add(line);
        findings.push({
          ruleId: cargoBuildRsNetwork.id,
          severity: "block",
          score: 9,
          file: ctx.path,
          line,
          snippet: truncateSnippet(m[0]),
          reason: `\`build.rs\` performs network IO at compile time. Fetching code or binaries from the network during a build is a supply-chain malware delivery vector.`,
          evidence: { marker: m[0] }
        });
      }
    }
    return findings;
  }
};

// ../core/dist/detectors/gha-curl-pipe-shell.js
function isWorkflow(p) {
  return /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(p);
}
var CURL_PIPE_SHELL_RE2 = /(?:curl|wget|fetch)\b[^\n]{0,200}\|\s*(?:bash|sh|zsh|python|node|perl|powershell|pwsh)\b/g;
var ghaCurlPipeShell = {
  id: "obf.gha-curl-pipe-shell",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfgha-curl-pipe-shell",
  applies(ctx) {
    return isWorkflow(ctx.path);
  },
  run(ctx) {
    const findings = [];
    const src = ctx.source;
    const re = new RegExp(CURL_PIPE_SHELL_RE2.source, CURL_PIPE_SHELL_RE2.flags);
    let m;
    while ((m = re.exec(src)) !== null) {
      findings.push({
        ruleId: ghaCurlPipeShell.id,
        severity: "block",
        score: 9,
        file: ctx.path,
        line: lineAtOffset(src, m.index),
        snippet: truncateSnippet(m[0]),
        reason: `GitHub Actions step pipes a network download into a shell. Pin the artifact (sha256) or fetch + verify before executing.`,
        evidence: { command: m[0] }
      });
    }
    return findings;
  }
};

// ../core/dist/detectors/dockerfile-curl-pipe-shell.js
function isDockerfile(p) {
  const base = p.slice(p.lastIndexOf("/") + 1);
  return base === "Dockerfile" || base.startsWith("Dockerfile.");
}
var RUN_CURL_PIPE_RE = /^\s*RUN\b[^\n]{0,500}(?:curl|wget|fetch)\b[^\n]{0,200}\|\s*(?:bash|sh|zsh|python|node|perl|powershell|pwsh)\b/gm;
var dockerfileCurlPipeShell = {
  id: "obf.dockerfile-curl-pipe-shell",
  docsUrl: "https://github.com/bytebardorg/obfuscan/blob/main/docs/detectors.md#obfdockerfile-curl-pipe-shell",
  applies(ctx) {
    return isDockerfile(ctx.path);
  },
  run(ctx) {
    const findings = [];
    const src = ctx.source;
    const re = new RegExp(RUN_CURL_PIPE_RE.source, RUN_CURL_PIPE_RE.flags);
    let m;
    while ((m = re.exec(src)) !== null) {
      findings.push({
        ruleId: dockerfileCurlPipeShell.id,
        severity: "block",
        score: 9,
        file: ctx.path,
        line: lineAtOffset(src, m.index),
        snippet: truncateSnippet(m[0].trim()),
        reason: `Dockerfile RUN pipes a network download into a shell. Pin the artifact (sha256) or fetch + verify before executing.`,
        evidence: { command: m[0].trim() }
      });
    }
    return findings;
  }
};

// ../core/dist/detectors/index.js
function defaultDetectors() {
  return DEFAULTS;
}
var DEFAULTS = Object.freeze([
  // Layer A
  highEntropyLiteral,
  bidiControlChar,
  homoglyphIdentifier,
  longLine,
  encodedArrayFingerprint,
  // Layer B
  decodeThenExec,
  networkThenExec,
  dynamicExecNonLiteral,
  deserializerUntrusted,
  suspiciousIoCluster,
  npmC2Dropper,
  stringArrayDecoder,
  shellUntrustedInput,
  libraryLoadNonLiteral,
  // Manifest
  manifestInstallScript,
  pythonSetupSideEffect,
  perlMakefileSideEffect,
  cargoBuildRsNetwork,
  ghaCurlPipeShell,
  dockerfileCurlPipeShell
]);

// ../core/dist/version.js
import { createRequire } from "node:module";
import * as path2 from "node:path";
import { fileURLToPath as fileURLToPath2 } from "node:url";
var cached = null;
var here2 = path2.dirname(fileURLToPath2(import.meta.url));
var ENGINE_VERSION = (() => {
  if (cached)
    return cached;
  const placeholder = "__ENGINE_VERSION__";
  if (placeholder !== "__ENGINE_VERSION__") {
    cached = placeholder;
    return cached;
  }
  try {
    const req = createRequire(import.meta.url);
    const candidates = [
      path2.resolve(here2, "..", "package.json"),
      path2.resolve(here2, "..", "..", "package.json")
    ];
    for (const c of candidates) {
      try {
        const pkg = req(c);
        if (pkg.name === "@obfuscan/core" && typeof pkg.version === "string") {
          cached = pkg.version;
          return cached;
        }
      } catch {
      }
    }
  } catch {
  }
  cached = "0.0.0-source";
  return cached;
})();

// ../core/dist/scan.js
var SEVERITY_RANK2 = { info: 0, warn: 1, block: 2 };
var DEFAULT_FILE_TIMEOUT_MS = 5e3;
var SNIPPET_CAP = 200;
async function scan(input2, options) {
  validateInput(input2);
  const t0 = Date.now();
  const logger = options.logger ?? consoleLogger();
  const ruleSet = options.rules ?? await defaultRuleSet();
  const detectors = (options.detectors ?? defaultDetectors()).filter((d) => !(options.disabledDetectors ?? []).includes(d.id));
  const targets = await prepareTargets(input2);
  const results = [];
  const findings = [];
  const failedDetectors = /* @__PURE__ */ new Set();
  const minRank = SEVERITY_RANK2[options.minSeverity ?? "info"];
  const fileTimeout = options.fileTimeoutMs ?? DEFAULT_FILE_TIMEOUT_MS;
  const concurrency = Math.max(1, options.concurrency ?? Math.max(2, defaultConcurrency()));
  let filesDone = 0;
  const total = targets.length;
  const reportProgress = (currentFile) => {
    if (!options.onProgress)
      return;
    const progress = currentFile ? { filesTotal: total, filesDone, currentFile } : { filesTotal: total, filesDone };
    options.onProgress(progress);
  };
  await runWithConcurrency(targets, concurrency, async (target) => {
    reportProgress(target.path);
    let source = null;
    try {
      source = await options.fileResolver(target.path);
    } catch (e) {
      logger.warn(`fileResolver threw for ${target.path}`, e);
    }
    let languageId = null;
    if (source !== null) {
      languageId = ruleSet.detectLanguage(target.path);
    }
    results.push({ path: target.path, languageId });
    if (source === null) {
      filesDone++;
      reportProgress();
      return;
    }
    const config = languageId ? ruleSet.configFor(languageId) : null;
    let cachedGrammar = null;
    let cachedTree = null;
    let treeResolved = false;
    const ctx = {
      path: target.path,
      languageId,
      config,
      source,
      addedRanges: target.addedRanges,
      grammar: null,
      // populated lazily if a detector accesses it
      tree: async () => {
        if (treeResolved)
          return cachedTree;
        treeResolved = true;
        if (!languageId)
          return null;
        try {
          cachedGrammar = await ruleSet.loadGrammar(languageId);
          if (cachedGrammar && typeof cachedGrammar.parse === "function") {
            cachedTree = await cachedGrammar.parse(source);
          } else {
            cachedTree = null;
          }
        } catch {
          cachedTree = null;
        }
        return cachedTree;
      }
    };
    Object.defineProperty(ctx, "grammar", {
      get() {
        return cachedGrammar;
      },
      enumerable: true
    });
    const directives = extractDisableDirectives(source);
    const fileFindings = [];
    for (const det of detectors) {
      let applies = false;
      try {
        applies = det.applies(ctx);
      } catch (e) {
        logger.warn(`detector ${det.id} threw in applies()`, e);
        failedDetectors.add(det.id);
        continue;
      }
      if (!applies)
        continue;
      let detFindings = [];
      try {
        const out = await runWithTimeout(det, ctx, fileTimeout);
        detFindings = out;
      } catch (e) {
        logger.warn(`detector ${det.id} failed on ${target.path}`, e);
        failedDetectors.add(det.id);
        continue;
      }
      for (const f of detFindings) {
        const normalized = normalizeFinding(f);
        if (target.diffMode && !lineInRanges(normalized.line, target.addedRanges)) {
          continue;
        }
        if (isSuppressedByDirectives(normalized.line, normalized.ruleId, directives)) {
          continue;
        }
        if (options.allowlist && matchesAllowlist(normalized, options.allowlist, target.path)) {
          continue;
        }
        if (SEVERITY_RANK2[normalized.severity] < minRank)
          continue;
        fileFindings.push(normalized);
      }
    }
    if (options.symbolResolver) {
      for (let i = 0; i < fileFindings.length; i++) {
        const f = fileFindings[i];
        try {
          const sym = await options.symbolResolver(target.path, f.line);
          if (sym)
            fileFindings[i] = { ...f, enclosingSymbol: sym };
        } catch {
        }
      }
    }
    findings.push(...fileFindings);
    filesDone++;
    reportProgress();
  });
  if (options.onProgress && total === 0) {
    options.onProgress({ filesTotal: 0, filesDone: 0 });
  }
  findings.sort(compareFindings);
  return {
    findings: Object.freeze(findings.slice()),
    files: Object.freeze(results.slice()),
    durationMs: Math.max(0, Date.now() - t0),
    failedDetectors: Object.freeze([...failedDetectors].sort()),
    rulesVersion: ruleSet.version(),
    engineVersion: ENGINE_VERSION
  };
}
function validateInput(input2) {
  const set = [
    input2.diff !== void 0,
    input2.paths !== void 0,
    input2.dir !== void 0
  ].filter(Boolean).length;
  if (set !== 1) {
    throw new InvalidScanInputError(`ScanInput must set exactly one of {diff, paths, dir}; got ${set}`);
  }
}
async function prepareTargets(input2) {
  if (input2.diff !== void 0) {
    const files = parseDiffToFiles(input2.diff);
    return files.filter((f) => f.status !== "deleted").map((f) => ({ path: f.path, addedRanges: f.addedRanges, diffMode: true }));
  }
  if (input2.paths !== void 0) {
    return input2.paths.map((p) => ({ path: p, addedRanges: [], diffMode: false }));
  }
  return [];
}
async function runWithConcurrency(items, limit, worker) {
  if (items.length === 0)
    return;
  let cursor = 0;
  const runners = [];
  const runOne = async () => {
    while (cursor < items.length) {
      const idx = cursor++;
      const item = items[idx];
      if (item === void 0)
        continue;
      await worker(item);
    }
  };
  for (let i = 0; i < Math.min(limit, items.length); i++) {
    runners.push(runOne());
  }
  await Promise.all(runners);
}
async function runWithTimeout(det, ctx, timeoutMs) {
  const out = det.run(ctx);
  if (Array.isArray(out))
    return out;
  return new Promise((resolve4, reject) => {
    const timer = setTimeout(() => reject(new Error(`detector ${det.id} timed out after ${timeoutMs}ms`)), timeoutMs);
    Promise.resolve(out).then((v) => {
      clearTimeout(timer);
      resolve4(v);
    }, (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}
function normalizeFinding(f) {
  let snippet = f.snippet;
  if (snippet.length > SNIPPET_CAP) {
    snippet = snippet.slice(0, SNIPPET_CAP - 3) + "...";
  }
  return snippet === f.snippet ? f : { ...f, snippet };
}
function compareFindings(a, b) {
  const ra = SEVERITY_RANK2[a.severity];
  const rb = SEVERITY_RANK2[b.severity];
  if (ra !== rb)
    return rb - ra;
  if (a.score !== b.score)
    return b.score - a.score;
  if (a.file !== b.file)
    return a.file < b.file ? -1 : 1;
  return a.line - b.line;
}
function defaultConcurrency() {
  try {
    const n = globalThis.navigator?.hardwareConcurrency;
    if (typeof n === "number" && n > 0)
      return n;
  } catch {
  }
  return 4;
}
function consoleLogger() {
  return {
    debug: () => {
    },
    info: () => {
    },
    warn: (msg, meta) => console.warn(msg, meta ?? ""),
    error: (msg, meta) => console.error(msg, meta ?? "")
  };
}

// src/inputs.ts
function readInputs(env = process.env) {
  const fileTimeoutMs = parseOptionalPositiveInt(input(env, "file-timeout-ms"), "file-timeout-ms");
  return {
    githubToken: input(env, "github-token"),
    failOn: parseFailOn(input(env, "fail-on") || "block"),
    minSeverity: parseSeverity(input(env, "min-severity") || "info"),
    comment: parseBoolean(input(env, "comment") || "true"),
    maxFindings: parsePositiveInt(input(env, "max-findings") || "50", "max-findings"),
    allowlistPath: input(env, "allowlist-path") || ".obfuscan/allowlist.json",
    disabledDetectors: parseList(input(env, "disabled-detectors")),
    ...fileTimeoutMs === void 0 ? {} : { fileTimeoutMs }
  };
}
function input(env, name) {
  const key = `INPUT_${name.replace(/ /g, "_").replace(/-/g, "_").toUpperCase()}`;
  return (env[key] ?? "").trim();
}
function parseSeverity(value) {
  if (value === "info" || value === "warn" || value === "block") return value;
  throw new Error(`min-severity must be one of info, warn, block; got ${value}`);
}
function parseFailOn(value) {
  if (value === "block" || value === "warn" || value === "never") return value;
  throw new Error(`fail-on must be one of block, warn, never; got ${value}`);
}
function parseBoolean(value) {
  const normalized = value.toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  throw new Error(`boolean input must be true or false; got ${value}`);
}
function parsePositiveInt(value, name) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer; got ${value}`);
  }
  return parsed;
}
function parseOptionalPositiveInt(value, name) {
  if (!value) return void 0;
  return parsePositiveInt(value, name);
}
function parseList(value) {
  return value.split(/[\n,]/g).map((item) => item.trim()).filter(Boolean);
}

// src/generated.ts
var BUNDLED_ENGINE_VERSION = "0.2.0";

// src/report.ts
var MARKER = "<!-- obfuscan-report -->";
var SEVERITIES = ["block", "warn", "info"];
function reportMarker() {
  return MARKER;
}
function countFindings(findings) {
  return {
    block: findings.filter((f) => f.severity === "block").length,
    warn: findings.filter((f) => f.severity === "warn").length,
    info: findings.filter((f) => f.severity === "info").length
  };
}
function shouldFail(findings, failOn) {
  if (failOn === "never") return false;
  if (failOn === "block") return findings.some((f) => f.severity === "block");
  return findings.some((f) => f.severity === "block" || f.severity === "warn");
}
function formatMarkdown(result, options) {
  const counts = countFindings(result.findings);
  const total = result.findings.length;
  const shown = result.findings.slice(0, Math.max(1, options.maxFindings));
  const omitted = Math.max(0, total - shown.length);
  const status = total === 0 ? "No findings." : counts.block > 0 ? "Blocking findings found." : counts.warn > 0 ? "Warnings found." : "Informational findings found.";
  const lines = [
    MARKER,
    "## obfuscan report",
    "",
    `**Status:** ${status}`,
    "",
    "| Metric | Value |",
    "|---|---:|",
    `| Scanned files | ${result.files.length} |`,
    `| Findings | ${total} |`,
    `| Block | ${counts.block} |`,
    `| Warn | ${counts.warn} |`,
    `| Info | ${counts.info} |`,
    `| Duration | ${result.durationMs} ms |`,
    `| Engine | ${escapeTable(options.engineVersion ?? result.engineVersion)} |`,
    `| Rules | ${escapeTable(options.rulesVersion ?? result.rulesVersion)} |`
  ];
  if (result.failedDetectors.length > 0) {
    lines.push(`| Failed detectors | ${escapeTable(result.failedDetectors.join(", "))} |`);
  }
  if (total === 0) {
    lines.push("", "No suspicious obfuscation or backdoor patterns were found in the scanned diff.");
    return lines.join("\n");
  }
  for (const severity of SEVERITIES) {
    const group = shown.filter((f) => f.severity === severity);
    if (group.length === 0) continue;
    lines.push("", `### ${titleCase(severity)} findings`, "");
    lines.push("| Location | Rule | Score | Reason | Snippet |");
    lines.push("|---|---|---:|---|---|");
    for (const finding of group) {
      lines.push(formatFindingRow(finding, options));
    }
  }
  if (omitted > 0) {
    lines.push("", `${omitted} additional finding${omitted === 1 ? "" : "s"} omitted from this comment.`);
  }
  lines.push("", "Suppress a known false positive with an in-source `obfuscan-disable-next-line` directive or `.obfuscan/allowlist.json`.");
  return lines.join("\n");
}
function formatFindingRow(finding, options) {
  const location = formatLocation(finding, options);
  const snippet = inlineCode(finding.snippet.replace(/\s+/g, " ").slice(0, 160));
  return [
    location,
    inlineCode(finding.ruleId),
    String(finding.score),
    escapeTable(finding.reason),
    snippet
  ].join(" | ").replace(/^/, "|").replace(/$/, "|");
}
function formatLocation(finding, options) {
  const label = `${finding.file}:${finding.line}`;
  if (!options.owner || !options.repo || !options.sha) return escapeTable(label);
  const path4 = finding.file.split("/").map(encodeURIComponent).join("/");
  return `[${escapeTable(label)}](https://github.com/${options.owner}/${options.repo}/blob/${options.sha}/${path4}#L${finding.line})`;
}
function inlineCode(value) {
  const escaped = escapeTable(value).replace(/`/g, "&#96;");
  return `<code>${escaped}</code>`;
}
function escapeTable(value) {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\|/g, "&#124;").replace(/\r?\n/g, "<br>");
}
function titleCase(value) {
  return value.slice(0, 1).toUpperCase() + value.slice(1);
}

// src/index.ts
var execFileAsync = promisify(execFile);
async function main() {
  const inputs = readInputs();
  const workspace = process.env["GITHUB_WORKSPACE"] || process.cwd();
  configureBundledRulesDir();
  const context = await readGitHubContext();
  const diff = await readDiff(context, inputs.githubToken);
  const allowlist = await loadAllowlist2(path3.resolve(workspace, inputs.allowlistPath));
  const result = await scan(
    { diff },
    {
      fileResolver: fileResolver(workspace),
      allowlist,
      minSeverity: inputs.minSeverity,
      disabledDetectors: inputs.disabledDetectors,
      logger: actionLogger(),
      ...inputs.fileTimeoutMs === void 0 ? {} : { fileTimeoutMs: inputs.fileTimeoutMs }
    }
  );
  const report = formatMarkdown(result, {
    maxFindings: inputs.maxFindings,
    owner: context.owner,
    repo: context.repo,
    engineVersion: normalizeEngineVersion(result),
    ...context.sha ? { sha: context.sha } : {}
  });
  writeAnnotations(result.findings);
  await writeStepSummary(report);
  if (inputs.comment && context.pullNumber !== void 0) {
    await upsertPullRequestComment(context, inputs.githubToken, report);
  } else if (inputs.comment) {
    warning("comment=true is ignored outside pull_request events");
  }
  const counts = countFindings(result.findings);
  const fail = shouldFail(result.findings, inputs.failOn);
  await Promise.all([
    setOutput("findings-total", String(result.findings.length)),
    setOutput("findings-block", String(counts.block)),
    setOutput("findings-warn", String(counts.warn)),
    setOutput("findings-info", String(counts.info)),
    setOutput("conclusion", fail ? "fail" : "pass")
  ]);
  if (fail) {
    throw new Error(`obfuscan found findings at or above fail-on=${inputs.failOn}`);
  }
}
function configureBundledRulesDir() {
  if (process.env["OBFUSCAN_RULES_DIR"]) return;
  const here3 = path3.dirname(fileURLToPath3(import.meta.url));
  process.env["OBFUSCAN_RULES_DIR"] = path3.join(here3, "rules", "languages");
}
async function readGitHubContext() {
  const repository = process.env["GITHUB_REPOSITORY"];
  if (!repository || !repository.includes("/")) {
    throw new Error("GITHUB_REPOSITORY is required");
  }
  const [owner, repo] = repository.split("/", 2);
  const eventPath = process.env["GITHUB_EVENT_PATH"];
  const event = eventPath ? JSON.parse(await fs2.readFile(eventPath, "utf8")) : {};
  const eventName = process.env["GITHUB_EVENT_NAME"] || "";
  const pullRequest = event["pull_request"];
  const baseApiUrl = process.env["GITHUB_API_URL"] || "https://api.github.com";
  const before = typeof event["before"] === "string" ? event["before"] : void 0;
  const after = typeof event["after"] === "string" ? event["after"] : void 0;
  const sha = readHeadSha(event) || process.env["GITHUB_SHA"];
  return {
    owner,
    repo,
    eventName,
    apiUrl: baseApiUrl.replace(/\/$/, ""),
    event,
    ...typeof pullRequest?.["number"] === "number" ? { pullNumber: pullRequest["number"] } : {},
    ...sha ? { sha } : {},
    ...before ? { before } : {},
    ...after ? { after } : {}
  };
}
function readHeadSha(event) {
  const pullRequest = event["pull_request"];
  const head = pullRequest?.["head"];
  return typeof head?.["sha"] === "string" ? head["sha"] : void 0;
}
async function readDiff(context, token) {
  if (context.pullNumber !== void 0) {
    return githubRequestText(
      context,
      token,
      `/repos/${context.owner}/${context.repo}/pulls/${context.pullNumber}`,
      "application/vnd.github.v3.diff"
    );
  }
  if (context.eventName === "push" && context.before && context.after) {
    return githubRequestText(
      context,
      token,
      `/repos/${context.owner}/${context.repo}/compare/${context.before}...${context.after}`,
      "application/vnd.github.diff"
    );
  }
  return readLocalDiff();
}
async function readLocalDiff() {
  try {
    const { stdout } = await execFileAsync("git", ["diff", "--no-ext-diff", "--unified=0", "HEAD~1...HEAD"], {
      maxBuffer: 50 * 1024 * 1024
    });
    return stdout;
  } catch (err) {
    throw new Error(`unable to determine a diff for this event: ${String(err)}`);
  }
}
async function loadAllowlist2(filePath) {
  try {
    const raw = await fs2.readFile(filePath, "utf8");
    return JSON.parse(raw);
  } catch {
    return {};
  }
}
function fileResolver(workspace) {
  const root = path3.resolve(workspace);
  return async (relativePath) => {
    const full = path3.resolve(root, relativePath);
    if (full !== root && !full.startsWith(root + path3.sep)) return null;
    try {
      const stat2 = await fs2.stat(full);
      if (!stat2.isFile()) return null;
      return await fs2.readFile(full, "utf8");
    } catch {
      return null;
    }
  };
}
async function upsertPullRequestComment(context, token, body) {
  if (!token) {
    warning("github-token is empty; skipping pull request comment");
    return;
  }
  if (context.pullNumber === void 0) return;
  try {
    const comments = await githubRequestJson(
      context,
      token,
      `/repos/${context.owner}/${context.repo}/issues/${context.pullNumber}/comments?per_page=100`,
      "GET"
    );
    const existing = comments.find((comment) => comment.body?.includes(reportMarker()));
    if (existing) {
      await githubRequestJson(
        context,
        token,
        `/repos/${context.owner}/${context.repo}/issues/comments/${existing.id}`,
        "PATCH",
        { body }
      );
    } else {
      await githubRequestJson(
        context,
        token,
        `/repos/${context.owner}/${context.repo}/issues/${context.pullNumber}/comments`,
        "POST",
        { body }
      );
    }
  } catch (err) {
    warning(`failed to write pull request comment: ${String(err)}`);
  }
}
async function githubRequestText(context, token, route, accept) {
  const response = await fetch(context.apiUrl + route, {
    headers: githubHeaders(token, accept)
  });
  if (!response.ok) {
    throw new Error(`GitHub API ${route} failed with ${response.status}: ${await response.text()}`);
  }
  return response.text();
}
async function githubRequestJson(context, token, route, method, body) {
  const response = await fetch(context.apiUrl + route, {
    method,
    headers: {
      ...githubHeaders(token, "application/vnd.github+json"),
      ...body === void 0 ? {} : { "content-type": "application/json" }
    },
    ...body === void 0 ? {} : { body: JSON.stringify(body) }
  });
  if (!response.ok) {
    throw new Error(`GitHub API ${method} ${route} failed with ${response.status}: ${await response.text()}`);
  }
  return response.json();
}
function githubHeaders(token, accept) {
  return {
    accept,
    "user-agent": "obfuscan-github-action",
    "x-github-api-version": "2022-11-28",
    ...token ? { authorization: `Bearer ${token}` } : {}
  };
}
function writeAnnotations(findings) {
  for (const finding of findings) {
    const command = finding.severity === "block" ? "error" : finding.severity === "warn" ? "warning" : "notice";
    const title = finding.ruleId;
    const message = `${finding.reason}
${finding.snippet}`;
    console.log(`::${command} file=${escapeProperty(finding.file)},line=${finding.line},title=${escapeProperty(title)}::${escapeData(message)}`);
  }
}
async function writeStepSummary(report) {
  const summaryPath = process.env["GITHUB_STEP_SUMMARY"];
  if (!summaryPath) return;
  await fs2.appendFile(summaryPath, report + "\n", "utf8");
}
async function setOutput(name, value) {
  const outputPath = process.env["GITHUB_OUTPUT"];
  if (!outputPath) {
    console.log(`${name}=${value}`);
    return;
  }
  try {
    await fs2.appendFile(outputPath, `${name}=${value}
`, "utf8");
  } catch (err) {
    warning(`failed to set output ${name}: ${String(err)}`);
  }
}
function actionLogger() {
  return {
    debug: (msg) => console.log(`::debug::${escapeData(msg)}`),
    info: (msg) => console.log(msg),
    warn: (msg) => warning(msg),
    error: (msg) => console.log(`::error::${escapeData(msg)}`)
  };
}
function normalizeEngineVersion(result) {
  return result.engineVersion === "0.0.0-source" ? BUNDLED_ENGINE_VERSION : result.engineVersion;
}
function warning(message) {
  console.log(`::warning::${escapeData(message)}`);
}
function escapeData(value) {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function escapeProperty(value) {
  return escapeData(value).replace(/:/g, "%3A").replace(/,/g, "%2C");
}
main().catch((err) => {
  console.log(`::error::${escapeData(err instanceof Error ? err.message : String(err))}`);
  process.exitCode = 1;
});
