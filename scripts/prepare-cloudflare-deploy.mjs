import { readFileSync, writeFileSync } from "node:fs";
import { createHash, randomInt } from "node:crypto";

const WRANGLER_FILE = "wrangler.jsonc";
const PACKAGE_FILE = "package.json";

const readJson = (file) => JSON.parse(readFileSync(file, "utf8"));
const sanitizeName = (value) => {
  const cleaned = String(value || "myvps")
    .replace(/-worker$/i, "")
    .replace(/[^a-z0-9]/gi, "")
    .toLowerCase();
  return cleaned || "myvps";
};

const stableRandomSuffix = () => {
  const seed = [
    process.env.CF_ACCOUNT_ID,
    process.env.CLOUDFLARE_ACCOUNT_ID,
    process.env.GITHUB_REPOSITORY,
    process.env.GITLAB_PROJECT_PATH,
    process.env.CF_WORKER_NAME,
  ].filter(Boolean).join(":");

  if (!seed) return String(randomInt(0, 1000)).padStart(3, "0");
  const number = createHash("sha256").update(seed).digest().readUInt32BE(0) % 1000;
  return String(number).padStart(3, "0");
};

const wrangler = readJson(WRANGLER_FILE);
const pkg = readJson(PACKAGE_FILE);
const projectName = sanitizeName(wrangler.name || pkg.name || "myvps");
const expectedPlaceholder = `${projectName}000`;
const database = wrangler.d1_databases?.find((item) => item.binding === "DB");

if (database && (!database.database_name || database.database_name === expectedPlaceholder || /-db$/i.test(database.database_name))) {
  database.database_name = `${projectName}${stableRandomSuffix()}`;
  writeFileSync(WRANGLER_FILE, `${JSON.stringify(wrangler, null, 2)}\n`);
  console.log(`Prepared Cloudflare D1 database name: ${database.database_name}`);
}
