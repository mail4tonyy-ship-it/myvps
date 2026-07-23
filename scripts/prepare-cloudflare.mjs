import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const configPath = resolve(root, "wrangler.jsonc");

function randomThreeDigits() {
  return String(Math.floor(Math.random() * 999) + 1).padStart(3, "0");
}

function normalizeName(value) {
  return String(value || "worker")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40) || "worker";
}

const config = JSON.parse(readFileSync(configPath, "utf8"));
const projectName = normalizeName(process.env.CF_PROJECT_NAME || config.name);
const d1 = config.d1_databases?.find(binding => binding.binding === "DB");

if (!d1) {
  console.log("[prepare-cloudflare] No DB binding found, skipping.");
  process.exit(0);
}

config.name = projectName;

const currentDatabaseName = String(d1.database_name || "");
const expectedPattern = new RegExp(`^${projectName}\\d{3}$`);
if (!expectedPattern.test(currentDatabaseName) || currentDatabaseName === `${projectName}000`) {
  d1.database_name = `${projectName}${randomThreeDigits()}`;
  delete d1.database_id;
  delete d1.preview_database_id;
  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
  console.log(`[prepare-cloudflare] D1 database will be auto-created as ${d1.database_name}.`);
} else {
  delete d1.database_id;
  delete d1.preview_database_id;
  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
  console.log(`[prepare-cloudflare] D1 database name already matches rule: ${d1.database_name}.`);
}
