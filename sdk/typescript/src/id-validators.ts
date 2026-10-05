// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * Guards for `*_id` identifier values: PII shape, and placeholders.
 * Direct port of Python's `fabric._id_validators` — the message intent,
 * sentinel tables and env-var switches are identical so both SDKs accept
 * and reject the same identifiers.
 *
 * **PII shape** ({@link warnIfPiiShaped}) — if callers pass values that
 * *look* like an email address or a phone number, those values silently
 * leave the process and ship to the trace backend with every decision —
 * a quiet PII leak that the developer never asked for. One warning per
 * (field, value) pair is emitted per process; set
 * `FABRIC_QUIET_PII_WARN=1` to suppress all such warnings. The intent is
 * *not* validation — opaque-but-email-shaped IDs are sometimes
 * intentional. The intent is to make the silent leak loud exactly once.
 *
 * **Placeholder identifiers** ({@link checkIdentifier}) — here the intent
 * *is* validation, but narrowly. `tenantId` and `agentId` are the
 * partition keys of every trace, every audit record and every tenant
 * isolation check downstream. A value of `"undefined"`, `"null"` or
 * `"${TENANT}"` is never a real tenant; it is an unset variable or an
 * unsubstituted template. Accepting it silently merges unrelated tenants
 * into one bogus partition.
 *
 * Two tiers, both deliberately narrow:
 *
 * - **Tier A — reject** (sentinel values plus unsubstituted template
 *   shapes). These cannot be a deliberate identifier under any reading.
 *   Throws, consistent with the empty-`tenantId` rejection.
 *   `FABRIC_ALLOW_PLACEHOLDER_IDS=1` downgrades the throw to a warning —
 *   it demotes, it does not silence.
 * - **Tier B — warn** (copy-paste markers). Values like `"changeme"` or
 *   `"your-tenant"` are overwhelmingly an uncopied quickstart snippet,
 *   but they *are* syntactically valid identifiers. Warn only.
 *
 * Deliberately **NOT** validated: length, character set/format, case,
 * and environment-ish names such as `test`/`staging` — real tenants use
 * them. Near-misses of the sentinels (`na`, `nullify-corp`, `nonesuch`)
 * are accepted: Tier A matches the whole stripped value, never a
 * substring.
 */

const ENV_QUIET = "FABRIC_QUIET_PII_WARN";
const ENV_ALLOW_PLACEHOLDER = "FABRIC_ALLOW_PLACEHOLDER_IDS";

// Regex shapes for PII-shaped identifiers — deliberately permissive to err
// on the side of flagging. Byte-identical to the Python patterns.
const LIKELY_EMAIL = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const LIKELY_PHONE = /^\+?\d{7,15}$|^\+?\d[\d -]{8,}\d$/;

// Embedded variants for free-form text fields (interaction kind, raw
// target): PII shows up INSIDE the string there, so anchored matches
// would miss it. Email stays distinctive (requires @ + dotted TLD). SSN
// and phone require separators or a leading + so plain digit runs like
// "id.12345678" don't flag.
const LIKELY_SSN_EMBEDDED = /\b\d{3}-\d{2}-\d{4}\b/;
const LIKELY_PHONE_EMBEDDED = /\+\d[\d -]{8,}\d|\b\d{3}[-. ]\d{3}[-. ]\d{4}\b/;

// Embedded scanning must stay cheap on adversarial input: an unanchored
// `[...]+@` regex retries from every start position, which is ~quadratic
// on long no-match strings and would stall the instrumented agent — the
// interference this SDK promises never to cause. Two bounds keep it
// linear-or-small: (1) the scan window is capped at the Node's
// `max_field_bytes` (anything longer is truncated at the boundary anyway,
// so PII past the cap never ships), and (2) a literal-substring prescreen
// skips each pattern when its mandatory character is absent.
const EMBEDDED_SCAN_LIMIT = 8192;
const EMAIL_LOCAL_CHARS = "._%+-";

function utf8Prefix(value: string, maxBytes: number): string {
  let used = 0;
  const chars: string[] = [];
  for (const char of value) {
    const codepoint = char.codePointAt(0) ?? 0;
    const size = codepoint <= 0x7f ? 1 : codepoint <= 0x7ff ? 2 : codepoint <= 0xffff ? 3 : 4;
    if (used + size > maxBytes) break;
    chars.push(char);
    used += size;
  }
  return chars.join("");
}

function isAsciiAlpha(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function isAsciiAlnum(code: number): boolean {
  return isAsciiAlpha(code) || (code >= 48 && code <= 57);
}

/** Match the embedded-email shape in one pass without regex retries. */
function containsEmbeddedEmail(value: string): boolean {
  let localRun = 0;
  let inDomain = false;
  let domainLength = 0;
  let suffixLetters = 0;
  let suffixActive = false;

  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    const char = value.charAt(i);
    const localChar = isAsciiAlnum(code) || EMAIL_LOCAL_CHARS.includes(char);
    if (char === "@") {
      inDomain = localRun > 0;
      domainLength = 0;
      suffixLetters = 0;
      suffixActive = false;
      localRun = 0;
      continue;
    }

    if (inDomain) {
      const domainChar = isAsciiAlnum(code) || char === "." || char === "-";
      if (!domainChar) {
        inDomain = false;
        suffixActive = false;
      } else {
        if (char === ".") {
          suffixActive = domainLength > 0;
          suffixLetters = 0;
        } else if (suffixActive) {
          if (isAsciiAlpha(code)) {
            suffixLetters += 1;
            if (suffixLetters >= 2) return true;
          } else {
            suffixActive = false;
          }
        }
        domainLength += 1;
      }
    }

    localRun = localChar ? localRun + 1 : 0;
  }
  return false;
}

/**
 * Tier A. Stringified absence — never a deliberate identifier. Matched
 * case-insensitively against the whitespace-stripped value.
 */
const SENTINEL_VALUES: ReadonlySet<string> = new Set([
  "undefined",
  "null",
  "none",
  "nil",
  "nan",
  "n/a",
  "(null)",
  "<null>",
  "<none>",
  "<undefined>",
]);

/**
 * Tier B. Copy-paste markers from docs and quickstarts. Matched after
 * lower-casing and removing `-`/`_`/space, so `replace-me`, `REPLACE_ME`
 * and `Replace Me` all match a single entry. Warn only.
 *
 * Deliberately absent: `my-agent` — the docs ship it as a worked example
 * value and it is a plausible real name for a single-agent deployment.
 */
const COPY_PASTE_MARKERS: ReadonlySet<string> = new Set([
  "changeme",
  "replaceme",
  "todo",
  "tbd",
  "fixme",
  "yourtenant",
  "youragent",
  "tenantid",
  "agentid",
  "mytenant",
]);

// Unsubstituted template shapes. `${VAR}` / `{{ var }}` cover shell, Helm,
// Jinja and Go templates; `%s` / `%(name)s` cover printf-style
// interpolation that was never applied. Full `<...>` wrapping is the
// universal docs convention for "put your value here".
const TEMPLATE_MARKERS = ["${", "{{"];
const PRINTF_TEMPLATE = /^%(s|\([A-Za-z_][A-Za-z0-9_]*\)s)$/;
const ANGLE_WRAPPED = /^<[^<>]*>$/;
const SEPARATORS = /[-_ ]+/g;

function isSentinel(value: string): boolean {
  if (SENTINEL_VALUES.has(value.toLowerCase())) {
    return true;
  }
  if (TEMPLATE_MARKERS.some((marker) => value.includes(marker))) {
    return true;
  }
  if (ANGLE_WRAPPED.test(value)) {
    return true;
  }
  return PRINTF_TEMPLATE.test(value);
}

function isCopyPasteMarker(value: string): boolean {
  return COPY_PASTE_MARKERS.has(value.toLowerCase().replace(SEPARATORS, ""));
}

// Warnings dedupe per process so a noisy-but-intentional identifier does
// not flood stderr. Keyed on the full message (which embeds field+value),
// matching Python's warnings-filter dedupe of the same call site.
const warnedMessages = new Set<string>();

function warnOnce(message: string): void {
  if (warnedMessages.has(message)) {
    return;
  }
  warnedMessages.add(message);
  console.warn(`Warning: ${message}`);
}

/**
 * Reject placeholder `value` for `fieldName`, or warn on markers.
 *
 * Called for `tenantId` and `agentId` only — the two fields that
 * partition every trace and every downstream isolation check.
 *
 * Throws when `value` is stringified absence (`undefined`, `null`,
 * `none`, `nil`, `nan`, `n/a`, `(null)`) or an unsubstituted template
 * (`${...}`, `{{...}}`, `<...>`, `%s`, `%(name)s`). Setting
 * `FABRIC_ALLOW_PLACEHOLDER_IDS=1` downgrades that throw to a warning.
 *
 * Emits a warning — never throws — when `value` is a copy-paste marker
 * such as `changeme` or `your-tenant`.
 *
 * No-ops on a falsy `value` — the caller has already rejected those.
 */
export function checkIdentifier(fieldName: string, value: string): void {
  if (!value || typeof value !== "string") {
    return;
  }
  if (isSentinel(value)) {
    const message =
      `${fieldName}=${JSON.stringify(value)} is a placeholder, not an identifier. ` +
      `This value partitions every span, audit record and tenant ` +
      `isolation check, so an unset variable here silently merges ` +
      `unrelated data. Set a real ${fieldName}. ` +
      `(to allow anyway, set ${ENV_ALLOW_PLACEHOLDER}=1)`;
    if (process.env[ENV_ALLOW_PLACEHOLDER] === "1") {
      warnOnce(message);
      return;
    }
    throw new Error(message);
  }
  if (isCopyPasteMarker(value)) {
    warnOnce(
      `${fieldName}=${JSON.stringify(value)} looks like an unedited copy-paste ` +
        `placeholder from the docs. It will be written onto every ` +
        `emitted span as a real ${fieldName}.`,
    );
  }
}

/**
 * Emit a one-shot stderr warning if `value` looks like PII.
 *
 * Cheap on the hot path: two compiled-regex matches against short
 * identifier strings, deduped per process.
 *
 * No-ops when `value` is falsy or non-string, or when
 * `FABRIC_QUIET_PII_WARN=1` is set in the environment.
 *
 * `embedded: true` searches for PII-shaped substrings instead of
 * requiring the whole value to match — use it for free-form text fields
 * (`interaction.kind`, a raw `interaction.target`) where an email, SSN,
 * or formatted phone number would appear embedded in longer
 * caller-controlled text.
 */
export function warnIfPiiShaped(
  fieldName: string,
  value: string | null | undefined,
  options: { embedded?: boolean } = {},
): void {
  if (!value || typeof value !== "string") {
    return;
  }
  if (process.env[ENV_QUIET] === "1") {
    return;
  }
  let matched: string | null = null;
  if (options.embedded) {
    const scan = utf8Prefix(value, EMBEDDED_SCAN_LIMIT);
    const hasDigit = /\d/.test(scan);
    if (scan.includes("@") && containsEmbeddedEmail(scan)) matched = "an email";
    else if (hasDigit && scan.includes("-") && LIKELY_SSN_EMBEDDED.test(scan)) matched = "an SSN";
    else if (
      hasDigit &&
      (scan.includes("+") || scan.includes("-") || scan.includes(".") || scan.includes(" ")) &&
      LIKELY_PHONE_EMBEDDED.test(scan)
    ) {
      matched = "a phone number";
    }
  } else if (LIKELY_EMAIL.test(value)) {
    matched = "an email";
  } else if (LIKELY_PHONE.test(value)) {
    matched = "a phone number";
  }
  if (matched !== null) {
    warnOnce(
      `${fieldName}=${JSON.stringify(value)} looks like ${matched} — these will ` +
        `appear in every emitted span, exporting PII to your trace ` +
        `backend. Consider an opaque ID instead and put the value in a ` +
        `separate non-emitted attribute. ` +
        `(suppress with FABRIC_QUIET_PII_WARN=1)`,
    );
  }
}
