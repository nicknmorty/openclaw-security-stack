#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const EXCLUDE_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "vendor",
  "third_party",
  "dist",
  "build",
  "coverage",
  "__pycache__",
  ".next",
  ".turbo",
]);

const SOURCE_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".cpp",
  ".cxx",
  ".h",
  ".hpp",
  ".go",
  ".rs",
  ".py",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".java",
  ".kt",
  ".rb",
  ".php",
  ".cs",
  ".swift",
]);

const CONFIG_EXTENSIONS = new Set([
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".md",
  ".tf",
  ".ini",
  ".conf",
  ".config",
]);

const PATTERNS = [
  {
    kind: "http",
    entryPoint: "HTTP routes and web callbacks",
    regex:
      /\b(app\.(get|post|put|delete|patch)|router\.(get|post|put|delete|patch)|express\(|fastify\(|createServer\(|fetch\(|axios\.|@app\.route|Flask\(|Django|http\.HandleFunc|ServeHTTP|actix_web|Rocket::|Controller\b|RequestMapping|PostMapping|GetMapping)\b/,
    boundary: "remote request -> application logic",
    assets: ["user data", "service availability", "authorization state"],
    threat: "Unauthorized access, data exposure, or state mutation through HTTP-facing application logic",
    actor: "remote_unauth",
    impact: "high",
    likelihood: "possible",
    mitigation: "Require explicit auth middleware and input validation on every externally reachable route",
  },
  {
    kind: "message",
    entryPoint: "Messaging and callback ingestion",
    regex:
      /\b(telegram|discord|slack|twilio|webhook|callback|message_id|chat_id|sender_id|fromMe|replyTo|sendMessage|sendSticker|sendPhoto)\b/i,
    boundary: "external message -> agent decision path",
    assets: ["tool authority", "private conversation context", "authorization state"],
    threat: "Untrusted message content is treated as trusted instruction and amplified through tools",
    actor: "remote_unauth",
    impact: "critical",
    likelihood: "likely",
    mitigation: "Separate message content from authority metadata and enforce tool gates before action",
  },
  {
    kind: "tool-exec",
    entryPoint: "Tool execution and shell command dispatch",
    regex:
      /\b(exec|spawn|spawnSync|execFile|execSync|child_process|subprocess|system\(|popen|ProcessBuilder|Command::new|Bash\(|apply_patch|write_stdin)\b/,
    boundary: "agent plan -> host command execution",
    assets: ["host integrity", "secrets", "tool authority"],
    threat: "Prompt-injected or incorrectly scoped instructions trigger unsafe host command execution",
    actor: "remote_unauth",
    impact: "critical",
    likelihood: "possible",
    mitigation: "Use per-task allowlists, dry-run review, and explicit confirmation for destructive or access-changing commands",
  },
  {
    kind: "file",
    entryPoint: "File parsing and filesystem access",
    regex:
      /\b(readFile|writeFile|createReadStream|openSync|fs\.open|path\.join|Path\(|open\(|fopen|FileInputStream|read_to_string|WalkDir|glob|fast-glob|yaml\.load|JSON\.parse)\b/,
    boundary: "local or user-supplied path -> filesystem and parser logic",
    assets: ["local files", "secrets", "memory authority records"],
    threat: "Path confusion, unsafe parsing, or broad filesystem reads expose private local data",
    actor: "remote_auth",
    impact: "high",
    likelihood: "possible",
    mitigation: "Constrain file access to declared roots and redact sensitive evidence before reporting",
  },
  {
    kind: "memory",
    entryPoint: "Memory and durable authority writes",
    regex:
      /\b(memory|remember|MEMORY\.md|authority|ownerAllowFrom|admin|contacts|groups|incidents|write memory|memory_get|memory_search)\b/i,
    boundary: "conversation or tool output -> durable assistant memory",
    assets: ["memory authority records", "authorization state", "private conversation context"],
    threat: "Untrusted or weakly verified input poisons durable memory or authority records",
    actor: "remote_auth",
    impact: "critical",
    likelihood: "possible",
    mitigation: "Route durable memory writes through typed lanes with source, authority, and review checks",
  },
  {
    kind: "secret",
    entryPoint: "Secret and credential loading",
    regex:
      /\b(process\.env|getenv|dotenv|SecretRef|api[_-]?key|token|refresh_token|password|credential|private_key|Authorization|Bearer)\b/i,
    boundary: "runtime config -> credential-bearing process state",
    assets: ["secrets", "host integrity", "external service access"],
    threat: "Secrets are logged, written, shared, or exposed through diagnostics and reports",
    actor: "local_user",
    impact: "critical",
    likelihood: "likely",
    mitigation: "Keep credentials in approved secret stores and apply redaction before logs, reports, or chat output",
  },
  {
    kind: "plugin",
    entryPoint: "Plugin, skill, MCP, and connector loading",
    regex:
      /\b(plugin|connector|mcp|skill|install|marketplace|require\(|import\(|dynamic import|dlopen|loadLibrary|eval\(|new Function)\b/i,
    boundary: "package or skill artifact -> runtime capability set",
    assets: ["tool authority", "host integrity", "supply-chain integrity"],
    threat: "Untrusted extension code or metadata expands runtime capabilities beyond reviewed scope",
    actor: "supply_chain",
    impact: "critical",
    likelihood: "possible",
    mitigation: "Track extension inventory, pin trusted sources, and require review for capability expansion",
  },
  {
    kind: "db",
    entryPoint: "Database and query construction",
    regex:
      /\b(sql|query\(|rawQuery|executeQuery|SELECT |INSERT |UPDATE |DELETE |prisma\.\$queryRaw|knex\.raw|sequelize\.query|mongoose|redis|postgres|mysql|sqlite)\b/i,
    boundary: "application input -> persistent data store",
    assets: ["user data", "authorization state", "service availability"],
    threat: "Injection or missing authorization exposes or mutates persistent data",
    actor: "remote_auth",
    impact: "high",
    likelihood: "possible",
    mitigation: "Use parameterized queries and enforce authorization at the data-access boundary",
  },
  {
    kind: "network",
    entryPoint: "Outbound network and fetch surfaces",
    regex: /\b(fetch\(|axios\.|got\(|request\(|curl|http\.get|https\.get|URL\(|urllib|requests\.|net\.Dial|TcpStream)\b/,
    boundary: "agent or service logic -> external network",
    assets: ["private conversation context", "secrets", "service availability"],
    threat: "Untrusted input steers outbound requests or exfiltrates private local context",
    actor: "remote_unauth",
    impact: "high",
    likelihood: "possible",
    mitigation: "Gate external requests by purpose and strip private context from outbound payloads",
  },
  {
    kind: "supply-chain",
    entryPoint: "Dependency and build surfaces",
    regex:
      /\b(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|requirements\.txt|pyproject\.toml|Cargo\.lock|go\.sum|Dockerfile|curl\s+\|\s*(sh|bash)|npm install|pip install)\b/i,
    boundary: "dependency or build input -> runtime artifact",
    assets: ["supply-chain integrity", "host integrity", "tool authority"],
    threat: "Compromised dependency or build step ships attacker-controlled code into trusted runtime",
    actor: "supply_chain",
    impact: "critical",
    likelihood: "possible",
    mitigation: "Inventory lockfiles, pin reviewed sources, and alert on package or install-script drift",
  },
];

function usage() {
  return `Usage: node scripts/security-threat-model.mjs <target-dir> [options]

Static, read-only threat-model bootstrapper for OpenClaw security-stack work.

Options:
  --out <path>          Markdown output path. Default: runs/threat-model/<target>/THREAT_MODEL.md
  --json-out <path>     JSON output path. Default: sibling threat-model.json
  --name <name>         System name for the generated model.
  --owner <name>        Owner/provenance label. Default: unset
  --inputs <text>       Extra provenance input label. Default: static repo inspection
  --max-files <n>       Max files to inspect. Default: 800
  --max-bytes <n>       Max bytes to read per file. Default: 120000
  --force               Overwrite existing output paths.
  --help                Show this help.
`;
}

function parseArgs(argv) {
  const args = {
    target: null,
    out: null,
    jsonOut: null,
    name: null,
    owner: "unset",
    inputs: "static repo inspection",
    maxFiles: 800,
    maxBytes: 120000,
    force: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (arg === "--force") {
      args.force = true;
      continue;
    }
    const valueOptions = new Set([
      "--out",
      "--json-out",
      "--name",
      "--owner",
      "--inputs",
      "--max-files",
      "--max-bytes",
    ]);
    if (valueOptions.has(arg)) {
      const value = argv[i + 1];
      if (!value || value.startsWith("--")) {
        throw new Error(`${arg} requires a value`);
      }
      i += 1;
      if (arg === "--out") args.out = value;
      if (arg === "--json-out") args.jsonOut = value;
      if (arg === "--name") args.name = value;
      if (arg === "--owner") args.owner = value;
      if (arg === "--inputs") args.inputs = value;
      if (arg === "--max-files") args.maxFiles = parsePositiveInteger(value, arg);
      if (arg === "--max-bytes") args.maxBytes = parsePositiveInteger(value, arg);
      continue;
    }
    if (arg.startsWith("--")) {
      throw new Error(`Unknown option: ${arg}`);
    }
    if (args.target) {
      throw new Error(`Unexpected extra positional argument: ${arg}`);
    }
    args.target = arg;
  }

  if (!args.target) {
    throw new Error("Missing target directory");
  }
  return args;
}

function parsePositiveInteger(value, label) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

function safeSlug(input) {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "target";
}

function resolveOutputPaths(args, targetDir) {
  const name = args.name || detectName(targetDir);
  const defaultDir = path.join(
    process.cwd(),
    "runs",
    "threat-model",
    safeSlug(name),
  );
  const markdownPath = path.resolve(args.out || path.join(defaultDir, "THREAT_MODEL.md"));
  const jsonPath = path.resolve(args.jsonOut || path.join(path.dirname(markdownPath), "threat-model.json"));
  return { name, markdownPath, jsonPath };
}

function detectName(targetDir) {
  const packageJson = path.join(targetDir, "package.json");
  if (fs.existsSync(packageJson)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(packageJson, "utf8"));
      if (typeof parsed.name === "string" && parsed.name.trim()) {
        return parsed.name.trim();
      }
    } catch {
      // fall through to directory name
    }
  }
  return path.basename(targetDir);
}

function collectFiles(root, maxFiles) {
  const files = [];
  const queue = [root];
  while (queue.length > 0 && files.length < maxFiles) {
    const current = queue.shift();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      const rel = path.relative(root, fullPath);
      if (entry.isDirectory()) {
        if (!EXCLUDE_DIRS.has(entry.name)) queue.push(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const ext = path.extname(entry.name);
      const lowerName = entry.name.toLowerCase();
      const isLockOrManifest =
        lowerName.includes("lock") ||
        ["package.json", "requirements.txt", "pyproject.toml", "cargo.toml", "go.mod", "dockerfile"].includes(lowerName);
      const isEnvTemplate =
        lowerName === ".env.example" ||
        lowerName === ".env.sample" ||
        lowerName === ".env.template" ||
        lowerName === "env.example" ||
        lowerName === "env.sample";
      if (SOURCE_EXTENSIONS.has(ext) || CONFIG_EXTENSIONS.has(ext) || isLockOrManifest || isEnvTemplate) {
        files.push({ rel, fullPath, ext, name: entry.name });
      }
      if (files.length >= maxFiles) break;
    }
  }
  return files;
}

function readSample(file, maxBytes) {
  try {
    const stat = fs.statSync(file.fullPath);
    if (stat.size > maxBytes) {
      const fd = fs.openSync(file.fullPath, "r");
      const buffer = Buffer.alloc(maxBytes);
      const read = fs.readSync(fd, buffer, 0, maxBytes, 0);
      fs.closeSync(fd);
      return buffer.subarray(0, read).toString("utf8");
    }
    return fs.readFileSync(file.fullPath, "utf8");
  } catch {
    return "";
  }
}

function detectLanguages(files) {
  const counts = new Map();
  for (const file of files) {
    const label = languageForExtension(file.ext, file.name);
    if (!label) continue;
    counts.set(label, (counts.get(label) || 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([language, count]) => ({ language, count }));
}

function languageForExtension(ext, name) {
  const lowerName = name.toLowerCase();
  if (lowerName === "dockerfile") return "Docker";
  const map = new Map([
    [".js", "JavaScript"],
    [".jsx", "JavaScript"],
    [".mjs", "JavaScript"],
    [".cjs", "JavaScript"],
    [".ts", "TypeScript"],
    [".tsx", "TypeScript"],
    [".py", "Python"],
    [".go", "Go"],
    [".rs", "Rust"],
    [".c", "C/C++"],
    [".cc", "C/C++"],
    [".cpp", "C/C++"],
    [".cxx", "C/C++"],
    [".h", "C/C++"],
    [".hpp", "C/C++"],
    [".java", "Java"],
    [".kt", "Kotlin"],
    [".rb", "Ruby"],
    [".php", "PHP"],
    [".cs", "C#"],
    [".swift", "Swift"],
    [".tf", "Terraform"],
    [".yaml", "YAML"],
    [".yml", "YAML"],
    [".json", "JSON"],
    [".toml", "TOML"],
  ]);
  return map.get(ext) || null;
}

function buildFindings(root, files, maxBytes) {
  const matches = new Map();
  for (const pattern of PATTERNS) {
    matches.set(pattern.kind, { pattern, files: [] });
  }
  for (const file of files) {
    const text = readSample(file, maxBytes);
    if (!text) continue;
    const searchable = `${file.rel}\n${text}`;
    for (const pattern of PATTERNS) {
      if (!pattern.regex.test(searchable)) continue;
      const firstLine = firstMatchingLine(text, pattern.regex);
      matches.get(pattern.kind).files.push({
        path: file.rel,
        line: firstLine,
      });
    }
  }
  return [...matches.values()].filter((entry) => entry.files.length > 0);
}

function firstMatchingLine(text, regex) {
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    regex.lastIndex = 0;
    if (regex.test(lines[i])) return i + 1;
  }
  return 1;
}

function inferAssets(matches) {
  const assets = new Map();
  const add = (asset, description, sensitivity) => {
    if (!assets.has(asset)) assets.set(asset, { asset, description, sensitivity });
  };

  add("host integrity", "The local host, filesystem, runtime process, and command execution environment.", "critical");
  add("service availability", "Availability of the target service or tool for legitimate users.", "medium");
  add("supply-chain integrity", "Dependency, build, and extension inputs that become trusted runtime code.", "high");

  for (const match of matches) {
    for (const asset of match.pattern.assets) {
      if (asset === "secrets") add(asset, "Tokens, keys, OAuth material, env values, and credentials.", "critical");
      else if (asset === "tool authority") add(asset, "Capabilities to execute tools, send messages, write files, or change system state.", "critical");
      else if (asset === "authorization state") add(asset, "Owner/admin identity, allowlists, bindings, and permission decisions.", "critical");
      else if (asset === "memory authority records") add(asset, "Durable memory and project records that shape future assistant behavior.", "high");
      else if (asset === "private conversation context") add(asset, "Private user messages, contact details, and local assistant context.", "high");
      else if (asset === "user data") add(asset, "Application data controlled by users or tenants.", "high");
      else if (asset === "local files") add(asset, "Files reachable from the scanned repository or configured roots.", "high");
      else add(asset, `Asset inferred from ${match.pattern.entryPoint}.`, "medium");
    }
  }

  return [...assets.values()].sort((a, b) => {
    const rank = { critical: 0, high: 1, medium: 2, low: 3 };
    return rank[a.sensitivity] - rank[b.sensitivity] || a.asset.localeCompare(b.asset);
  });
}

function makeEntryPoints(matches) {
  return matches.map((match) => {
    const refs = match.files
      .slice(0, 5)
      .map((file) => `${file.path}:${file.line}`)
      .join(", ");
    return {
      entry_point: match.pattern.entryPoint,
      description: `${match.files.length} representative file(s) matched. Examples: ${refs}.`,
      trust_boundary: match.pattern.boundary,
      reachable_assets: match.pattern.assets.join(", "),
      kind: match.pattern.kind,
      refs,
    };
  });
}

function makeThreats(matches) {
  return matches
    .map((match, index) => ({
      id: `T${index + 1}`,
      threat: match.pattern.threat,
      actor: match.pattern.actor,
      surface: match.pattern.entryPoint,
      asset: match.pattern.assets.join(", "),
      impact: match.pattern.impact,
      likelihood: match.pattern.likelihood,
      status: "partially_mitigated",
      controls: "unknown from static bootstrap; requires owner/code review",
      evidence: match.files.slice(0, 5).map((file) => `${file.path}:${file.line}`).join(", "),
      mitigation: match.pattern.mitigation,
      effort: defaultEffort(match.pattern.kind),
    }))
    .sort(compareThreats)
    .map((threat, index) => ({ ...threat, id: `T${index + 1}` }));
}

function defaultEffort(kind) {
  if (["secret", "memory", "message"].includes(kind)) return "M";
  if (["tool-exec", "plugin", "supply-chain"].includes(kind)) return "L";
  return "M";
}

function compareThreats(a, b) {
  const impactRank = { existential: 5, critical: 4, high: 3, medium: 2, low: 1 };
  const likelihoodRank = {
    almost_certain: 5,
    likely: 4,
    possible: 3,
    rare: 2,
    very_rare: 1,
  };
  return (
    impactRank[b.impact] - impactRank[a.impact] ||
    likelihoodRank[b.likelihood] - likelihoodRank[a.likelihood] ||
    a.threat.localeCompare(b.threat)
  );
}

function summarizeContext(name, targetLabel, files, languages, matches) {
  const topLanguages = languages
    .slice(0, 4)
    .map((item) => `${item.language} (${item.count})`)
    .join(", ") || "unknown language mix";
  const surfaces = matches.map((match) => match.pattern.entryPoint).join("; ") || "no obvious entry points";
  return `${name} is a local source tree labeled \`${targetLabel}\` with ${files.length} inspected source/config file(s). The dominant detected languages or manifest types are ${topLanguages}.

This bootstrap is static-only. It did not build, execute, fuzz, install dependencies, contact target infrastructure, or validate exploitability. The detected attack-surface candidates are: ${surfaces}. Treat this as a starting model for scanner scoping and owner review, not a final security assessment.`;
}

function makeMarkdown(model) {
  return `# Threat Model: ${escapePipe(model.name)}

## 1. System context

${model.system_context}

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
${model.assets.map((row) => `| ${escapePipe(row.asset)} | ${escapePipe(row.description)} | ${row.sensitivity} |`).join("\n")}

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
${model.entry_points.map((row) => `| ${escapePipe(row.entry_point)} | ${escapePipe(row.description)} | ${escapePipe(row.trust_boundary)} | ${escapePipe(row.reachable_assets)} |`).join("\n")}

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
${model.threats.map((row) => `| ${row.id} | ${escapePipe(row.threat)} | ${row.actor} | ${escapePipe(row.surface)} | ${escapePipe(row.asset)} | ${row.impact} | ${row.likelihood} | ${row.status} | ${escapePipe(row.controls)} | ${escapePipe(row.evidence)} |`).join("\n")}

## 5. Deprioritized

| threat | reason |
|---|---|
| Volumetric denial of service without a concrete code path | Security-stack V0 prioritizes concrete exploit paths, drift, secret exposure, and authority amplification over generic capacity planning. |

## 6. Open questions

${model.open_questions.map((question) => `- ${question}`).join("\n")}

## 7. Provenance

- mode: bootstrap
- date: ${model.date}
- target: ${escapePipe(model.target_label)}${model.git_commit ? ` @ ${model.git_commit}` : ""}
- inputs: ${escapePipe(model.inputs)}
- owner: ${escapePipe(model.owner)}
- generated_by: scripts/security-threat-model.mjs
- source_reference: https://github.com/anthropics/defending-code-reference-harness

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
${model.threats.map((row) => `| ${escapePipe(row.mitigation)} | ${row.id} | partial | ${row.effort} |`).join("\n")}
`;
}

function escapePipe(value) {
  return String(value ?? "")
    .replace(/\|/g, "\\|")
    .replace(/\r?\n/g, " ")
    .trim();
}

function buildModel(args, targetDir, outputName) {
  const files = collectFiles(targetDir, args.maxFiles);
  const languages = detectLanguages(files);
  const matches = buildFindings(targetDir, files, args.maxBytes);
  const assets = inferAssets(matches);
  const entryPoints = makeEntryPoints(matches);
  const threats = makeThreats(matches);
  const git = gitMetadata(targetDir);
  const targetBasename = path.basename(targetDir);
  const targetLabel = outputName || targetBasename;
  const openQuestions = [
    "Which detected entry points are actually reachable by untrusted users in production?",
    "Which controls already exist outside this repository, such as gateway auth, sandboxing, firewall rules, or deployment policy?",
    "Which threats should be accepted, downgraded, or split after owner review?",
  ];
  if (threats.length === 0) {
    openQuestions.unshift("No obvious entry points matched the static heuristics; manually identify the trust boundaries before scanner work.");
  }

  return {
    schema_version: "security-stack.threat-model.v1",
    tool: "security-threat-model",
    name: outputName,
    date: new Date().toISOString().slice(0, 10),
    target_label: targetLabel,
    target_basename: targetBasename,
    git_commit: git.commit,
    inputs: args.inputs,
    owner: args.owner,
    file_count: files.length,
    languages,
    local_private: {
      local_target_path: targetDir,
    },
    system_context: summarizeContext(outputName, targetLabel, files, languages, matches),
    assets,
    entry_points: entryPoints,
    threats,
    open_questions: openQuestions,
  };
}

function gitMetadata(targetDir) {
  const headPath = path.join(targetDir, ".git", "HEAD");
  try {
    const head = fs.readFileSync(headPath, "utf8").trim();
    if (head.startsWith("ref: ")) {
      const refPath = path.join(targetDir, ".git", head.slice(5));
      const commit = fs.readFileSync(refPath, "utf8").trim();
      return { commit: commit ? commit.slice(0, 12) : null };
    }
    return { commit: head ? head.slice(0, 12) : null };
  } catch {
    return { commit: null };
  }
}

function writeOutput(filePath, content, force) {
  if (fs.existsSync(filePath) && !force) {
    throw new Error(`Refusing to overwrite ${filePath}; pass --force to replace it`);
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    const targetDir = path.resolve(args.target);
    const stat = fs.statSync(targetDir);
    if (!stat.isDirectory()) {
      throw new Error(`Target is not a directory: ${targetDir}`);
    }

    const { name, markdownPath, jsonPath } = resolveOutputPaths(args, targetDir);
    const model = buildModel(args, targetDir, name);
    const markdown = makeMarkdown(model);
    writeOutput(markdownPath, markdown, args.force);
    writeOutput(jsonPath, `${JSON.stringify(model, null, 2)}\n`, args.force);

    console.log(`Threat model written: ${markdownPath}`);
    console.log(`JSON written: ${jsonPath}`);
    console.log(`Inspected files: ${model.file_count}`);
    console.log(`Threats: ${model.threats.length}`);
    for (const threat of model.threats.slice(0, 5)) {
      console.log(`- ${threat.id}: ${threat.impact}/${threat.likelihood} ${threat.threat}`);
    }
  } catch (error) {
    console.error(`security-threat-model: ${error.message}`);
    console.error("");
    console.error(usage());
    process.exit(1);
  }
}

main();
