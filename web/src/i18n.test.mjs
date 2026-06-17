import assert from "node:assert/strict";
import test from "node:test";

import { createTranslator, languages, translations } from "./i18n.js";

test("supports Chinese and English language options", () => {
  assert.deepEqual(languages.map((language) => language.id), ["zh", "en"]);
  assert.equal(languages[0].label, "中文");
  assert.equal(languages[1].label, "English");
});

test("translates shared dashboard labels in both languages", () => {
  const zh = createTranslator("zh");
  const en = createTranslator("en");

  assert.equal(zh("nav.dashboard"), "仪表盘");
  assert.equal(en("nav.dashboard"), "Dashboard");
  assert.equal(zh("kpi.attackSuccessRate"), "攻击成功率");
  assert.equal(en("kpi.attackSuccessRate"), "Attack Success Rate");
});

test("falls back to Chinese and then the key when a translation is missing", () => {
  const unknownLanguage = createTranslator("fr");
  const english = createTranslator("en");

  assert.equal(unknownLanguage("nav.chat"), translations.zh["nav.chat"]);
  assert.equal(english("missing.key"), "missing.key");
});
