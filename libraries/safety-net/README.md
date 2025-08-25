---

# safe-pass

A zero-dependency TypeScript/JavaScript library for password strength validation and safe input handling.

---

## Features

* **Password validation** with entropy estimation and weak-pattern detection.
* **Strict input filtering** with configurable allow-lists.
* **Safe rendering helpers** for untrusted data.
* **Server-side validation** utilities.
* **Fully customizable policies** — you choose allowed characters, length ranges, and password thresholds.

---

## Installation

```bash
npm install @gurpratap/safe-pass
```

---

## Usage

### Password Validation

```ts
import { validatePassword } from "@gurpratapsmagh/safe-pass";

const res = validatePassword("P@ssw0rd1234");
console.log(res);

/*
{
  ok: false,
  score: 1,
  entropyBits: 78,
  issues: ["common_password", "sequential_chars"],
  suggestions: ["Avoid common passwords...", "Avoid sequences like..."]
}
*/
```

**Inputs:** string `password`
**Outputs:** `{ ok, score, entropyBits, issues[], suggestions[] }`

#### Custom Policy Example

```ts
const r = validatePassword("Tr0n!Canoe-maple-93");
if (r.entropyBits < 100 || r.score < 3) {
  throw new Error("Password too weak");
}
```

👉 You decide the cutoff for score/entropy/length.

### Input Filtering

```ts
import { createSafeXssInput } from "@gurpratapsmagh/safe-pass";

// Only allow lowercase letters + digits, max length 16
const { filter, bind } = createSafeXssInput("abcdefghijklmnopqrstuvwxyz0123456789", { maxLength: 16 });

console.log(filter("Hello<script>WORLD!!"));
// { value: "helloworld", rejected: ["<","s","c",...], isClean: false }

const input = document.querySelector("#username");
bind(input); // dynamically enforces your allow-list
```

👉 You define the character set — it can be strict ASCII, extended Unicode, or even emoji.

### Safe Rendering

```ts
import { setText, escapeHTML, setSafeAttr } from "@gurpratapsmagh/safe-pass";

setText(document.getElementById("out"), "<b>Not bold</b>");
// rendered literally as text

console.log(escapeHTML("<img>"));
// "&lt;img&gt;"

const link = document.createElement("a");
setSafeAttr(link, "href", "http://example.com");
// valid href, unsafe protocols are blocked
```

### Server-Side Validation

```ts
import { validateAllowedServer } from "@gurpratapsmagh/safe-pass";

// Validate username server-side
const username = validateAllowedServer("hello123", "abcdefghijklmnopqrstuvwxyz0123456789", 3, 24);

if (!username) {
  // reject request
} else {
  // safe normalized value
}
```

---

## API

* `validatePassword(password, opts?)` → object with `ok`, `score`, `entropyBits`, `issues[]`, `suggestions[]`
* `createSafeXssInput(allowed, opts?)` → `{ filter(raw), bind(element) }`
* `setText(el, value)` → safely sets text content
* `escapeHTML(str)` → returns HTML-escaped string
* `setSafeAttr(el, name, value)` → sets attributes safely, blocks dangerous protocols
* `validateAllowedServer(raw, allowed, min, max)` → returns normalized value or `null`

---

## Notes

* Client-side filtering is for UX only; **always validate on the server**.
* Use safe rendering (`textContent`, `setText`) to avoid **Cross-Site Scripting (XSS)**.
* Pair with a **Content-Security-Policy (CSP)** for stronger protection.
* Library does not dictate security thresholds — **you configure policies** (allowed chars, max length, password entropy cutoffs).
