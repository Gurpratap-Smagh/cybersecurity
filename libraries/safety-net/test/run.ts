import { validatePassword, createSafeXssInput } from "../dist/index";

// Sample passwords
const samples = [
  "password",
  "P@ssw0rd1234",
  "Qwerty!2024",
  "aaaaAAAA1111!!!!",
  "Tr0n!Canoe-maple-93"
];

console.log("=== validatePassword ===");
for (const s of samples) {
  const r = validatePassword(s);
  console.log(
    `${s} => ok:${r.ok} score:${r.score} H≈${r.entropyBits} issues:[${r.issues.join(", ")}]`
  );
}

// Safe input filter test
console.log("\n=== createSafeXssInput.filter ===");
const { filter } = createSafeXssInput("abcdefghijklmnopqrstuvwxyz0123456789 _-", {
  toLower: true,
  maxLength: 24
});

console.log(filter("Hello<script>alert(1)</script>__WORLD!!"));
console.log("\nAll good ✅");