const test = require("node:test");
const assert = require("node:assert/strict");
const mail = require("./mail.js");

test("suspicious urls are defanged and credentials in the backend URL are rejected", () => {
  const urls = mail.extractSuspiciousUrls("See http://10.1.2.3/login and https://evil.xyz/a");
  assert.equal(urls.length, 2);
  assert.ok(urls.every((item) => !item.defanged.includes("http")));
  assert.equal(mail.normalizeBackendUrl("http://user:secret@127.0.0.1:8000"), "");
  assert.equal(mail.normalizeBackendUrl("http://127.0.0.1:8000/api"), "http://127.0.0.1:8000");
});

test("analysis payload truncates the body and does not record unless asked", () => {
  const payload = mail.buildAnalysisPayload({
    provider: "gmail",
    subject: "Account",
    sender: "a@example.test",
    body: "x".repeat(mail.MAX_BODY_CHARS + 25),
  }, false);
  assert.equal(payload.body.length, mail.MAX_BODY_CHARS);
  assert.equal(payload.truncated, true);
  assert.equal(payload.record, false);
  assert.equal(payload.provider, "gmail");
});
