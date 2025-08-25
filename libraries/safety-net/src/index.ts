/* ==========================================================
   safe-pass: password validator + strict allow-list filtering
   and safe text rendering helpers. Zero dependencies.
   ========================================================== */

/* ---------------- Password Validator ------------------- */

export type PasswordIssue =
  | "too_short"
  | "not_enough_variety"
  | "common_password"
  | "dictionary_word"
  | "sequential_chars"
  | "keyboard_sequence"
  | "repeated_chars"
  | "low_entropy";

export interface PolicyOptions {
  minLength?: number;            // default 12
  requireVariety?: boolean;      // default true (3/4 classes)
  minVarietyClasses?: number;    // default 3
  minEntropyBits?: number;       // default 50
  blacklist?: Set<string>;       // exact matches (lowercased)
  dictionary?: Set<string>;      // words to avoid (lowercased, leet-normalized)
}

export interface ValidationResult {
  ok: boolean;
  score: 0 | 1 | 2 | 3 | 4;
  entropyBits: number;
  issues: PasswordIssue[];
  suggestions: string[];
}

const DEFAULT_COMMON = [
  "password","passw0rd","p@ssw0rd","admin","welcome","letmein","qwerty","abc123",
  "111111","123456","123456789","iloveyou","dragon","monkey","football","baseball"
];

const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];

function leetNormalize(s: string): string {
  return s.toLowerCase()
    .replace(/@/g, "a")
    .replace(/3/g, "e")
    .replace(/[1!|]/g, "i")
    .replace(/0/g, "o")
    .replace(/5/g, "s")
    .replace(/7/g, "t");
}

function varietyClasses(pw: string): number {
  return [
    /[a-z]/.test(pw), /[A-Z]/.test(pw), /\d/.test(pw), /[^A-Za-z0-9]/.test(pw)
  ].filter(Boolean).length;
}

function hasSequentialChars(pw: string, span = 4): boolean {
  const s = pw.toLowerCase();
  const ord = (c: string) => c.charCodeAt(0);
  for (let i = 0; i <= s.length - span; i++) {
    let inc = true, dec = true;
    for (let j = 1; j < span; j++) {
      inc &&= ord(s[i + j]) === ord(s[i + j - 1]) + 1;
      dec &&= ord(s[i + j]) === ord(s[i + j - 1]) - 1;
    }
    if (inc || dec) return true;
  }
  return false;
}

function hasKeyboardSequence(pw: string, span = 4): boolean {
  const s = pw.toLowerCase();
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i <= row.length - span; i++) {
      const seq = row.slice(i, i + span);
      if (s.includes(seq) || s.includes([...seq].reverse().join(""))) return true;
    }
  }
  return false;
}

function hasLongRepeat(pw: string): boolean {
  // 3 of the same char in a row, or repeating chunks (e.g., abcabcabc)
  return /(.)\1{2,}/.test(pw) || /(.{2,4})\1{2,}/i.test(pw);
}

function estimateEntropyBits(pw: string): number {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  const bitsPerChar = Math.log2(Math.max(pool, 2));
  return Math.round(bitsPerChar * pw.length);
}

function containsDictionaryWord(pw: string, dict: Set<string>): boolean {
  const s = leetNormalize(pw.toLowerCase());
  for (const w of dict) {
    if (w.length >= 4 && (s.includes(w) || s === w)) return true;
  }
  return false;
}

/** Validate password strength with entropy estimate and readable reasons. */
export function validatePassword(
  password: string,
  opts: PolicyOptions = {}
): ValidationResult {
  const {
    minLength = 12,
    requireVariety = true,
    minVarietyClasses = 3,
    minEntropyBits = 50,
    blacklist = new Set(DEFAULT_COMMON),
    dictionary = new Set(DEFAULT_COMMON.concat([
      "qwerty","welcome","summer","winter","spring","autumn","hockey","soccer","canada"
    ])),
  } = opts;

  const issues: PasswordIssue[] = [];

  if (password.length < minLength) issues.push("too_short");
  if (requireVariety && varietyClasses(password) < minVarietyClasses) issues.push("not_enough_variety");
  if (blacklist.has(password.toLowerCase())) issues.push("common_password");
  if (containsDictionaryWord(password, dictionary)) issues.push("dictionary_word");
  if (hasSequentialChars(password)) issues.push("sequential_chars");
  if (hasKeyboardSequence(password)) issues.push("keyboard_sequence");
  if (hasLongRepeat(password)) issues.push("repeated_chars");

  const entropyBits = estimateEntropyBits(password);
  if (entropyBits < minEntropyBits) issues.push("low_entropy");

  const minor = new Set<PasswordIssue>(["low_entropy", "not_enough_variety"]);
  let score: 0 | 1 | 2 | 3 | 4 = 0;
  if (issues.length === 0) score = 4;
  else if (issues.length === 1 && minor.has(issues[0])) score = 3;
  else if (issues.length <= 2) score = 2;
  else if (issues.length <= 4) score = 1;
  else score = 0;

  const suggestions: string[] = [];
  if (issues.includes("too_short")) suggestions.push(`Use at least ${minLength}+ characters.`);
  if (issues.includes("not_enough_variety")) suggestions.push(`Add more types (upper/lower/digit/symbol).`);
  if (issues.includes("common_password")) suggestions.push(`Avoid common passwords (e.g., “password”, “123456”).`);
  if (issues.includes("dictionary_word")) suggestions.push(`Avoid dictionary words—even with l33t swaps.`);
  if (issues.includes("sequential_chars")) suggestions.push(`Avoid sequences like “abcd” or “7654”.`);
  if (issues.includes("keyboard_sequence")) suggestions.push(`Avoid keyboard runs like “qwerty” or “asdf”.`);
  if (issues.includes("repeated_chars")) suggestions.push(`Avoid repeats like “aaaa” or “abcabcabc”.`);
  if (issues.includes("low_entropy")) suggestions.push(`Make it longer and mix unrelated words + digits + symbols.`);

  return { ok: issues.length === 0, score, entropyBits, issues, suggestions };
}

/* --------------- Strict Allow-List Filtering --------------- */

export interface SafeInputOptions {
  /** Normalize to NFC before checking (prevents combining-mark tricks). Default true. */
  normalize?: boolean;
  /** Max accepted length (characters). Extra chars are dropped. */
  maxLength?: number;
  /** Trim leading/trailing whitespace after filtering. */
  trim?: boolean;
  /** Force lowercase before filtering (typical for usernames). */
  toLower?: boolean;
}

/**
 * Build a strict allow-list filter and optional DOM binder.
 * `allowed` is a string or array of literal characters (NO regex).
 * Example: "abcdefghijklmnopqrstuvwxyz0123456789 _-"
 */
export function createSafeXssInput(
  allowed: string | string[],
  options: SafeInputOptions = {}
) {
  const { normalize = true, maxLength, trim = false, toLower = false } = options;
  const set = new Set(typeof allowed === "string" ? [...allowed] : allowed);

  function filter(raw: string) {
    let input = normalize ? raw.normalize("NFC") : raw;
    if (toLower) input = input.toLowerCase();

    const out: string[] = [];
    const rejected: string[] = [];

    for (const cp of input) {
      if (set.has(cp)) {
        out.push(cp);
        if (maxLength && out.length >= maxLength) break;
      } else {
        rejected.push(cp);
      }
    }

    let value = out.join("");
    if (trim) value = value.trim();

    return {
      value,                 // <- contains only allowed characters
      rejected,              // <- what got dropped
      isClean: rejected.length === 0 && value.length === (trim ? input.trim().length : input.length),
    };
  }

  /**
   * Dynamically enforce allow-list on <input>/<textarea>:
   * - Prevents disallowed insertions early (beforeinput)
   * - Cleans up pasted/IME text
   * - Keeps cursor stable on correction
   */
  function bind(el: HTMLInputElement | HTMLTextAreaElement) {
    const onInput: EventListener = (e) => {
      const tgt = e.target as HTMLInputElement | HTMLTextAreaElement;
      const { value } = filter(tgt.value);
      if (tgt.value !== value) {
        const pos = tgt.selectionStart ?? value.length;
        tgt.value = value;
        const p = Math.min(pos, value.length);
        tgt.setSelectionRange(p, p);
      }
    };

    const onBeforeInput: EventListener = (e) => {
      // Narrow to InputEvent if available in this environment
      const ie = e as unknown as InputEvent;
      const type = (ie as any).inputType as string | undefined;
      const data = (ie as any).data as string | null | undefined;
      if (!type) return;

      if (type.startsWith("insert") || type === "insertFromPaste" || type === "insertCompositionText") {
        if (data) {
          let d = normalize ? data.normalize("NFC") : data;
          if (toLower) d = d.toLowerCase();
          for (const cp of d) {
            if (!set.has(cp)) {
              ie.preventDefault();
              return;
            }
          }
        }
      }
    };

    const onPaste: EventListener = (e) => {
      const ce = e as unknown as ClipboardEvent;
      const text = ce.clipboardData?.getData("text") ?? "";
      const { value } = filter(text);
      if (value !== text) {
        ce.preventDefault();
        const tgt = ce.target as HTMLInputElement | HTMLTextAreaElement;
        const start = tgt.selectionStart ?? 0;
        const end = tgt.selectionEnd ?? 0;
        const next = tgt.value.slice(0, start) + value + tgt.value.slice(end);
        tgt.value = next;
        const pos = start + value.length;
        tgt.setSelectionRange(pos, pos);
        tgt.dispatchEvent(new Event("input", { bubbles: true }));
      }
    };

    el.addEventListener("beforeinput", onBeforeInput);
    el.addEventListener("input", onInput);
    el.addEventListener("paste", onPaste);

    // initial sanitize
    onInput(new Event("input"));

    return () => {
      el.removeEventListener("beforeinput", onBeforeInput);
      el.removeEventListener("input", onInput);
      el.removeEventListener("paste", onPaste);
    };
  }

  return { filter, bind };
}

/* ------------------ Safe Text Rendering -------------------- */

/** Render untrusted text as literal text (never parsed as HTML). */
export function setText(el: HTMLElement, value: string) {
  el.textContent = "";                // clear
  el.appendChild(document.createTextNode(value));
}

/** Minimal HTML escaping helper (if you must build strings). Prefer setText() */
export function escapeHTML(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Safe attribute setter, blocks dangerous protocols in href/src. */
export function setSafeAttr(el: Element, name: string, value: string) {
  if (name === "href" || name === "src") {
    const u = new URL(value, typeof window !== "undefined" ? window.location.origin : "http://localhost");
    const okProto = ["http:", "https:"];
    if (!okProto.includes(u.protocol)) {
      throw new Error(`Blocked ${name} with protocol: ${u.protocol}`);
    }
  }
  el.setAttribute(name, value);
}

/* ---------------- Server-Side helper (optional) ------------ */

/**
 * Server-side strict validator for a username-like field.
 * Returns normalized value or null if invalid.
 */
export function validateAllowedServer(raw: string, allowed: string | string[], min = 3, max = 24): string | null {
  const set = new Set(typeof allowed === "string" ? [...allowed] : allowed);
  const s = raw.normalize("NFC").toLowerCase();
  if (s.length < min || s.length > max) return null;
  for (const cp of s) if (!set.has(cp)) return null;
  return s;
}
