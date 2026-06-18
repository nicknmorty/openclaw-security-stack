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
  "runs",
]);

const SCANNED_EXTENSIONS = new Set([
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
  ".yaml",
  ".yml",
  ".json",
  ".toml",
  ".tf",
]);

const SOURCE_HINT =
  /\b(req|request|params|query|body|message|payload|input|argv|args|stdin|env|headers|chat|sender|webhook|callback|user)\b/i;

const RULES = [
  {
    id: "unsafe-tool-exec",
    lane: "agent-safety",
    category: "command-execution",
    severity: "HIGH",
    confidence: 0.72,
    title: "Potentially unsafe command or tool execution from controllable input",
    sink: /\b(execFile|execSync|exec|spawnSync|spawn)\s*\(|\b(child_process|subprocess|popen|ProcessBuilder|Command::new)\b|\bsystem\s*\(|\btools\.exec\s*\(|\bBash\s*\(/,
    needsTaint: true,
    description:
      "A command/tool execution sink appears near request, message, argument, or other controllable input. This is a candidate for prompt-injected or user-steered execution.",
    recommendation:
      "Constrain commands to explicit allowlists, split trusted metadata from untrusted text, and require confirmation for destructive or access-changing operations.",
    threatKeywords: ["command", "tool", "host", "execution"],
  },
  {
    id: "path-traversal",
    lane: "runtime-health",
    category: "path-traversal",
    severity: "MEDIUM",
    confidence: 0.68,
    title: "User-controlled value appears in filesystem path operation",
    sink: /\b(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|openSync|fs\.open|path\.join|Path\(|open\(|fopen)\b/,
    needsTaint: true,
    description:
      "A filesystem operation appears near a request, message, or argument-derived value. Without root confinement and normalization this can expose or overwrite unintended files.",
    recommendation:
      "Resolve paths under an approved root, reject traversal, and keep sensitive paths out of shareable evidence.",
    threatKeywords: ["file", "filesystem", "path", "local files"],
  },
  {
    id: "secret-exposure",
    lane: "runtime-health",
    category: "secret-exposure",
    severity: "HIGH",
    confidence: 0.74,
    title: "Credential-like value may leave the approved secret boundary",
    sink: /\b(console\.(log|error|warn)|logger\.(info|debug|warn|error)|res\.(json|send)|reply|sendMessage|writeFile|writeFileSync|execFile|spawn|throw new Error)\b/,
    needsSecret: true,
    description:
      "A logging, response, write, or process boundary appears near credential-like values. This is a candidate for secret exposure through diagnostics or side effects.",
    recommendation:
      "Keep credentials in approved secret stores and redact or omit them before logs, reports, command arguments, and chat output.",
    threatKeywords: ["secret", "credential", "token", "diagnostic"],
  },
  {
    id: "memory-poisoning",
    lane: "agent-safety",
    category: "memory-poisoning",
    severity: "HIGH",
    confidence: 0.7,
    title: "Untrusted content may be written into durable memory or authority records",
    sink: /\bmemory\.(write|set|append)\s*\(|\bwriteMemory\s*\(|\bremember\s*\(|\bMEMORY\.md\b|\bownerAllowFrom\b|\bauthority\b/i,
    needsTaint: true,
    description:
      "Durable memory or authority-lane writes appear near message, request, or user-controlled content. This can preserve attacker-chosen context for future decisions.",
    recommendation:
      "Route memory writes through typed lanes with source attribution, authority checks, and human review for access or policy records.",
    threatKeywords: ["memory", "authority", "poison"],
  },
  {
    id: "dynamic-code-eval",
    lane: "agent-safety",
    category: "code-injection",
    severity: "HIGH",
    confidence: 0.76,
    title: "Dynamic code evaluation surface detected",
    sink: /\b(eval\(|new Function|vm\.runIn|Function\(|execScript|setTimeout\([^,]+,|setInterval\([^,]+,)\b/,
    needsTaint: false,
    description:
      "Dynamic code evaluation is present. If attacker-controlled text can reach this surface, it becomes code execution.",
    recommendation:
      "Remove dynamic evaluation or constrain it to a non-authoritative sandbox with strict input grammar and no secrets.",
    threatKeywords: ["eval", "code", "plugin", "extension"],
  },
  {
    id: "sql-injection",
    lane: "runtime-health",
    category: "sql-injection",
    severity: "HIGH",
    confidence: 0.73,
    title: "Raw query construction may include controllable input",
    sink: /\b(query\(|rawQuery|executeQuery|prisma\.\$queryRaw|knex\.raw|sequelize\.query|SELECT |INSERT |UPDATE |DELETE )\b/i,
    needsTaint: true,
    description:
      "A raw query surface appears near request, argument, or message-derived input. This is a candidate injection path unless parameters are enforced.",
    recommendation:
      "Use parameterized queries or ORM-safe APIs and enforce authorization at the data-access boundary.",
    threatKeywords: ["query", "sql", "data"],
  },
  {
    id: "ssrf-or-exfil",
    lane: "agent-safety",
    category: "outbound-request",
    severity: "MEDIUM",
    confidence: 0.62,
    title: "Outbound request may be steered by controllable input",
    sink: /\b(fetch\(|axios\.|got\(|request\(|http\.get|https\.get|urllib|requests\.|net\.Dial|TcpStream|URL\()\b/,
    needsTaint: true,
    description:
      "An outbound network call appears near user-controlled input. This can become SSRF or private-context exfiltration in agent systems.",
    recommendation:
      "Gate outbound requests by destination and purpose, and strip private local context from request payloads.",
    threatKeywords: ["network", "outbound", "exfil"],
  },
  {
    id: "raw-html-injection",
    lane: "runtime-health",
    category: "xss",
    severity: "MEDIUM",
    confidence: 0.65,
    title: "Raw HTML rendering surface detected",
    sink: /\b(dangerouslySetInnerHTML|v-html|bypassSecurityTrustHtml|innerHTML\s*=|insertAdjacentHTML)\b/,
    needsTaint: false,
    description:
      "Raw HTML rendering is present. If attacker-controlled content reaches this surface, framework escaping can be bypassed.",
    recommendation:
      "Avoid raw HTML rendering or sanitize with a reviewed allowlist at the trust boundary.",
    threatKeywords: ["html", "xss", "render"],
  },
  {
    id: "supply-chain-script",
    lane: "supply-chain",
    category: "supply-chain",
    severity: "MEDIUM",
    confidence: 0.64,
    title: "Install or build script can execute package-provided code",
    sink: /\b(preinstall|postinstall|prepare|curl\s+\|\s*(sh|bash)|npm install|pip install|scripts":)\b/i,
    needsTaint: false,
    description:
      "A dependency or build script execution surface was found. This is a candidate supply-chain amplification point.",
    recommendation:
      "Inventory dependency scripts, pin trusted sources, and alert on lockfile or install-script drift.",
    threatKeywords: ["supply", "dependency", "build"],
  },
  {
    id: "unauthenticated-mutation-route",
    lane: "runtime-health",
    category: "auth-bypass",
    severity: "MEDIUM",
    confidence: 0.42,
    title: "Mutating route may need explicit authentication review",
    sink: /\b(app|router)\.(post|put|patch|delete)\b/,
    needsMissingAuth: true,
    description:
      "A mutating route was found without nearby obvious authentication or authorization checks. This is a low-confidence review candidate.",
    recommendation:
      "Confirm authentication and authorization are enforced before mutation or sensitive side effects.",
    threatKeywords: ["auth", "authorization", "http"],
  },
];

function usage() {
  return `Usage: node scripts/security-static-scan.mjs <target-dir> [options]

Static, read-only candidate scanner for OpenClaw security-stack work.

Options:
  --threat-model <path>  Optional threat-model JSON from security-threat-model.mjs
  --out <path>           JSON output path. Default: runs/static-scan/<target>/VULN-FINDINGS.json
  --md-out <path>        Markdown output path. Default: sibling VULN-FINDINGS.md
  --name <name>          Run/system name. Default: target directory name
  --max-files <n>        Max files to inspect. Default: 1000
  --max-bytes <n>        Max bytes to read per file. Default: 160000
  --min-confidence <n>   Drop candidates below this score. Default: 0.4
  --include-tests        Include test, fixture, and example paths.
  --force                Overwrite existing outputs.
  --help                 Show this help.
`;
}

function parseArgs(argv) {
  const args = {
    target: null,
    threatModelPath: null,
    out: null,
    mdOut: null,
    name: null,
    maxFiles: 1000,
    maxBytes: 160000,
    minConfidence: 0.4,
    includeTests: false,
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
    if (arg === "--include-tests") {
      args.includeTests = true;
      continue;
    }
    const valueOptions = new Set([
      "--threat-model",
      "--out",
      "--md-out",
      "--name",
      "--max-files",
      "--max-bytes",
      "--min-confidence",
    ]);
    if (valueOptions.has(arg)) {
      const value = argv[i + 1];
      if (!value || value.startsWith("--")) throw new Error(`${arg} requires a value`);
      i += 1;
      if (arg === "--threat-model") args.threatModelPath = value;
      if (arg === "--out") args.out = value;
      if (arg === "--md-out") args.mdOut = value;
      if (arg === "--name") args.name = value;
      if (arg === "--max-files") args.maxFiles = parsePositiveInteger(value, arg);
      if (arg === "--max-bytes") args.maxBytes = parsePositiveInteger(value, arg);
      if (arg === "--min-confidence") args.minConfidence = parseConfidence(value, arg);
      continue;
    }
    if (arg.startsWith("--")) throw new Error(`Unknown option: ${arg}`);
    if (args.target) throw new Error(`Unexpected extra positional argument: ${arg}`);
    args.target = arg;
  }

  if (!args.target) throw new Error("Missing target directory");
  return args;
}

function parsePositiveInteger(value, label) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 1) throw new Error(`${label} must be a positive integer`);
  return parsed;
}

function parseConfidence(value, label) {
  const parsed = Number.parseFloat(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    throw new Error(`${label} must be between 0 and 1`);
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

function detectName(targetDir) {
  const packageJson = path.join(targetDir, "package.json");
  if (fs.existsSync(packageJson)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(packageJson, "utf8"));
      if (typeof parsed.name === "string" && parsed.name.trim()) return parsed.name.trim();
    } catch {
      // fall through
    }
  }
  return path.basename(targetDir);
}

function resolveOutputPaths(args, targetDir) {
  const name = args.name || detectName(targetDir);
  const defaultDir = path.join(process.cwd(), "runs", "static-scan", safeSlug(name));
  const jsonPath = path.resolve(args.out || path.join(defaultDir, "VULN-FINDINGS.json"));
  const markdownPath = path.resolve(args.mdOut || path.join(path.dirname(jsonPath), "VULN-FINDINGS.md"));
  return { name, jsonPath, markdownPath };
}

function loadThreatModel(threatModelPath) {
  if (!threatModelPath) return null;
  const resolved = path.resolve(threatModelPath);
  const parsed = JSON.parse(fs.readFileSync(resolved, "utf8"));
  return { ...parsed, source_path: resolved, source_label: path.basename(resolved) };
}

function collectFiles(root, maxFiles, includeTests) {
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
      if (entry.isDirectory()) {
        if (!EXCLUDE_DIRS.has(entry.name)) queue.push(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const ext = path.extname(entry.name);
      if (!SCANNED_EXTENSIONS.has(ext)) continue;
      const rel = path.relative(root, fullPath);
      if (!includeTests && isTestOrFixturePath(rel)) continue;
      files.push({ fullPath, rel, ext, role: evidenceRole(rel, entry.name) });
      if (files.length >= maxFiles) break;
    }
  }
  return files;
}

function evidenceRole(rel, name = path.basename(rel)) {
  const parts = rel.split(path.sep);
  if (isTestOrFixturePath(rel)) return "test";
  if (/^(docs?|documentation)$/i.test(parts[0]) || /\.(md|mdx|rst)$/i.test(name)) return "docs";
  if (/lock/i.test(name) || /^(package\.json|requirements\.txt|pyproject\.toml|cargo\.toml|go\.mod|dockerfile)$/i.test(name)) {
    return "lockfile/manifest";
  }
  if (/generated|\.gen\.|\.generated\./i.test(rel)) return "generated";
  return "source";
}

function isTestOrFixturePath(rel) {
  const parts = rel.split(path.sep);
  const base = parts[parts.length - 1] || "";
  return (
    /^test[-_.]/i.test(base) ||
    parts.some((part) =>
      /^(test|tests|fixture|fixtures|example|examples|__tests__|__fixtures__)$/i.test(part),
    )
  );
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

function scanFile(file, text, threatModel) {
  const findings = [];
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (isRuleDefinitionLine(line)) continue;
    const context = contextAround(lines, index, 4);
    for (const rule of RULES) {
      rule.sink.lastIndex = 0;
      if (!rule.sink.test(line)) continue;
      if (rule.needsTaint && !SOURCE_HINT.test(context)) continue;
      if (rule.needsSecret && !secretHint(context)) continue;
      if (rule.needsMissingAuth && hasAuthHint(contextAround(lines, index, 12))) continue;

      findings.push(makeFinding(rule, file, index + 1, line, context, threatModel));
    }
  }
  return findings;
}

function isRuleDefinitionLine(line) {
  return (
    /^\s*(id|kind|lane|category|title|description|recommendation|sink|regex|threatKeywords|entryPoint|boundary|assets|threat|actor|impact|likelihood|mitigation)\s*:/.test(line) ||
    /^\s*["'`].*["'`],?\s*$/.test(line) ||
    /^\s*(return\s+)?\/.+\/[a-z]*(\.test\(.*\))?;?,?\s*$/.test(line)
  );
}

function contextAround(lines, index, radius) {
  return lines
    .slice(Math.max(0, index - radius), Math.min(lines.length, index + radius + 1))
    .join("\n");
}

function secretHint(text) {
  return /\b(process\.env|getenv|api[_-]?key|token|refresh_token|password|secret|credential|private_key|Authorization|Bearer)\b/i.test(text);
}

function hasAuthHint(text) {
  return /\b(auth|authorize|authenticated|requireUser|requireAdmin|ownerAllowFrom|verify|token|permission|canAccess|isAdmin)\b/i.test(text);
}

function makeFinding(rule, file, lineNumber, line, context, threatModel) {
  const threatIds = matchThreatIds(rule, threatModel);
  return {
    id: "pending",
    lane: rule.lane,
    category: rule.category,
    title: rule.title,
    severity: rule.severity,
    confidence: rule.confidence,
    status: "new",
    verdict: "candidate",
    redaction_level: secretHint(context) ? "local" : "shareable-redacted",
    file: file.rel,
    line: lineNumber,
    surface: threatIds.surface,
    threat_ids: threatIds.ids,
    evidence: [
      {
        path: file.rel,
        line: lineNumber,
        role: file.role,
        snippet_redacted: redactSnippet(line.trim()),
      },
    ],
    description: rule.description,
    exploit_scenario: candidateScenario(rule, file.rel, lineNumber),
    recommendation: rule.recommendation,
    scanner: {
      name: "security-static-scan",
      rule_id: rule.id,
      mode: "static-readonly",
    },
  };
}

function matchThreatIds(rule, threatModel) {
  if (!threatModel || !Array.isArray(threatModel.threats)) {
    return { ids: [], surface: "unknown" };
  }
  const matches = threatModel.threats.filter((threat) => {
    const haystack = `${threat.id} ${threat.threat} ${threat.surface} ${threat.asset}`.toLowerCase();
    return rule.threatKeywords.some((keyword) => haystack.includes(keyword.toLowerCase()));
  });
  return {
    ids: matches.slice(0, 4).map((threat) => threat.id),
    surface: matches[0]?.surface || "unknown",
  };
}

function redactSnippet(snippet) {
  return snippet
    .replace(/(api[_-]?key|token|refresh_token|password|secret|credential|private_key)(\s*[:=]\s*)["'`]?[^"',`\s)]+/gi, "$1$2[REDACTED]")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
    .replace(/process\.env\.([A-Z0-9_]*TOKEN|[A-Z0-9_]*KEY|[A-Z0-9_]*SECRET|[A-Z0-9_]*PASSWORD)/g, "process.env.[REDACTED]");
}

function candidateScenario(rule, file, line) {
  const scenarios = {
    "unsafe-tool-exec": `If attacker-controlled text reaches ${file}:${line}, it may steer command/tool execution beyond the intended operation.`,
    "path-traversal": `If attacker-controlled path segments reach ${file}:${line}, they may read or write outside the intended root.`,
    "secret-exposure": `If credential-bearing values reach ${file}:${line}, they may appear in logs, responses, files, process arguments, or chat-visible output.`,
    "memory-poisoning": `If untrusted content reaches ${file}:${line}, it may persist into future assistant context or authority records.`,
    "dynamic-code-eval": `If attacker-controlled text reaches ${file}:${line}, it may execute as code.`,
    "sql-injection": `If attacker-controlled input reaches ${file}:${line}, it may alter the intended database query.`,
    "ssrf-or-exfil": `If attacker-controlled input reaches ${file}:${line}, it may steer outbound requests or leak private context.`,
    "raw-html-injection": `If attacker-controlled HTML reaches ${file}:${line}, it may bypass framework escaping.`,
    "supply-chain-script": `If this build/install surface changes unexpectedly at ${file}:${line}, trusted runtime code may be expanded by a dependency or script.`,
    "unauthenticated-mutation-route": `If this route is externally reachable and lacks upstream auth, ${file}:${line} may allow unauthorized mutation.`,
  };
  return scenarios[rule.id] || `Candidate exploit path at ${file}:${line} requires triage.`;
}

function dedupe(findings) {
  const byKey = new Map();
  for (const finding of findings) {
    const key = `${finding.scanner.rule_id}:${finding.file}:${finding.line}`;
    const prior = byKey.get(key);
    if (!prior || finding.confidence > prior.confidence) byKey.set(key, finding);
  }
  return [...byKey.values()];
}

function assignIds(findings) {
  return findings
    .sort(compareFindings)
    .map((finding, index) => ({
      ...finding,
      id: `F-${String(index + 1).padStart(3, "0")}`,
    }));
}

function compareFindings(a, b) {
  const severityRank = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  return (
    severityRank[b.severity] - severityRank[a.severity] ||
    b.confidence - a.confidence ||
    a.file.localeCompare(b.file) ||
    a.line - b.line
  );
}

function summarizeRun(name, targetDir, threatModel, files, findings) {
  const bySeverity = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  const byLane = {};
  for (const finding of findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    byLane[finding.lane] = (byLane[finding.lane] || 0) + 1;
  }
  const git = gitMetadata(targetDir);
  return {
    scanner: "security-static-scan",
    mode: "static-readonly",
    name,
    target_label: name,
    target_basename: path.basename(targetDir),
    target_commit: git.commit,
    local_private: {
      local_target_path: targetDir,
      local_threat_model_path: threatModel?.source_path || null,
    },
    date: new Date().toISOString(),
    threat_model: threatModel?.source_label || null,
    inspected_files: files.length,
    finding_count: findings.length,
    by_severity: bySeverity,
    by_lane: byLane,
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

function makeMarkdown(report) {
  const lines = [
    `# Static Scan Findings: ${report.summary.name}`,
    "",
    "## Summary",
    "",
    `- mode: ${report.summary.mode}`,
    `- target_label: ${report.summary.target_label}`,
    `- target_basename: ${report.summary.target_basename}`,
    `- target_commit: ${report.summary.target_commit || "none"}`,
    `- threat_model: ${report.summary.threat_model || "none"}`,
    `- inspected_files: ${report.summary.inspected_files}`,
    `- finding_count: ${report.summary.finding_count}`,
    `- high: ${report.summary.by_severity.HIGH || 0}`,
    `- medium: ${report.summary.by_severity.MEDIUM || 0}`,
    `- low: ${report.summary.by_severity.LOW || 0}`,
    "",
    "These are static candidate findings for triage, not verified vulnerabilities.",
    "",
    "## Findings",
    "",
  ];

  if (report.findings.length === 0) {
    lines.push("No candidate findings met the confidence threshold.");
    return `${lines.join("\n")}\n`;
  }

  for (const finding of report.findings) {
    lines.push(`### ${finding.id}: ${finding.title}`);
    lines.push("");
    lines.push(`- severity: ${finding.severity}`);
    lines.push(`- confidence: ${finding.confidence.toFixed(2)}`);
    lines.push(`- lane: ${finding.lane}`);
    lines.push(`- category: ${finding.category}`);
    lines.push(`- location: ${finding.file}:${finding.line}`);
    lines.push(`- threat_ids: ${finding.threat_ids.length ? finding.threat_ids.join(", ") : "none"}`);
    lines.push(`- redaction_level: ${finding.redaction_level}`);
    lines.push("");
    lines.push(finding.description);
    lines.push("");
    lines.push(`Exploit scenario: ${finding.exploit_scenario}`);
    lines.push("");
    lines.push(`Recommendation: ${finding.recommendation}`);
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
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
    if (!stat.isDirectory()) throw new Error(`Target is not a directory: ${targetDir}`);

    const { name, jsonPath, markdownPath } = resolveOutputPaths(args, targetDir);
    const threatModel = loadThreatModel(args.threatModelPath);
    const files = collectFiles(targetDir, args.maxFiles, args.includeTests);
    const allFindings = [];
    for (const file of files) {
      const text = readSample(file, args.maxBytes);
      if (!text) continue;
      allFindings.push(...scanFile(file, text, threatModel));
    }
    const findings = assignIds(
      dedupe(allFindings).filter((finding) => finding.confidence >= args.minConfidence),
    );
    const report = {
      schema_version: "security-stack.findings.v1",
      tool: "security-static-scan",
      summary: summarizeRun(name, targetDir, threatModel, files, findings),
      findings,
    };

    writeOutput(jsonPath, `${JSON.stringify(report, null, 2)}\n`, args.force);
    writeOutput(markdownPath, makeMarkdown(report), args.force);

    console.log(`Findings JSON written: ${jsonPath}`);
    console.log(`Findings Markdown written: ${markdownPath}`);
    console.log(`Inspected files: ${files.length}`);
    console.log(`Candidate findings: ${findings.length}`);
    for (const finding of findings.slice(0, 8)) {
      console.log(`- ${finding.id}: ${finding.severity}/${finding.confidence.toFixed(2)} ${finding.category} ${finding.file}:${finding.line}`);
    }
  } catch (error) {
    console.error(`security-static-scan: ${error.message}`);
    console.error("");
    console.error(usage());
    process.exit(1);
  }
}

main();
