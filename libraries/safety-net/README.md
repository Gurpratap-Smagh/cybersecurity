-----

# safe-pass

A zero-dependency TypeScript/JavaScript library for password strength validation and safe input handling.

-----

## Features

  - **Password validation** with entropy estimation and weak-pattern detection.
  - **Strict input filtering** with configurable allow-lists.
  - **Safe rendering helpers** for untrusted data.
  - **Server-side validation** utilities.

-----

## Installation

```bash
npm install @gurpratap/safe-pass
```

-----

## Usage

### Password Validation (frontend or API server)

```javascript
import { validatePassword } from "safe-pass";

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

### Input Filtering (frontend form fields)

```javascript
import { createSafeXssInput } from "safe-pass";

// only a–z0–9, space, _, -
const { filter, bind } = createSafeXssInput("abcdefghijklmnopqrstuvwxyz0123456789 _-", {
  toLower: true, maxLength: 24
});

console.log(filter("Hello<script>WORLD!!"));
// { value: "hello world", rejected: ["<","s","c",...,"!"], isClean: false }

const input = document.querySelector("#username");
bind(input); // dynamically enforces allowed chars
```

**Inputs:** raw string or DOM input
**Outputs:** cleaned value, rejected characters, boolean `isClean`

### Safe Rendering (frontend)

```javascript
import { setText, escapeHTML, setSafeAttr } from "safe-pass";

setText(document.getElementById("out"), "<b>Not bold</b>"); 
// rendered literally as text

console.log(escapeHTML("<img>")); 
// "&lt;img&gt;"

const link = document.createElement("a");
setSafeAttr(link, "href", "http://example.com"); 
// valid href, unsafe protocols are blocked
```

### Server-Side Validation (API)

```javascript
import { validateAllowedServer } from "safe-pass";

// validate username server-side
const username = validateAllowedServer("hello123", "abcdefghijklmnopqrstuvwxyz0123456789", 3, 24);

if (!username) {
  // reject request
} else {
  // safe normalized value
}
```

**Inputs:** raw string, allowed characters, min and max length
**Outputs:** normalized string or `null`

-----

## API

  - `validatePassword(password, opts?)` → object with `ok`, `score`, `entropyBits`, `issues[]`, `suggestions[]`
  - `createSafeXssInput(allowed, opts?)` → `{ filter(raw), bind(element) }`
  - `setText(el, value)` → safely sets text content
  - `escapeHTML(str)` → returns HTML-escaped string
  - `setSafeAttr(el, name, value)` → sets attributes safely, blocks dangerous protocols
  - `validateAllowedServer(raw, allowed, min, max)` → returns normalized value or `null`

-----

## Notes

  - Client-side filtering is for UX only; **always validate on the server**.
  - Use safe rendering (`textContent`, `setText`) to avoid **Cross-Site Scripting (XSS)**.
  - Pair with a **Content-Security-Policy (CSP)** for stronger protection.