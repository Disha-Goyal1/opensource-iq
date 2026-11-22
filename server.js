// OpenSource IQ backend: collect -> clean -> engineer -> score -> serve. Zero dependencies (Node 18+).
const http = require("http"), fs = require("fs"), path = require("path");
const PORT = process.env.PORT || 3000, GH_TOKEN = process.env.GITHUB_TOKEN;
const REG = "https://registry.npmjs.org", enc = (n) => n.replace("/", "%2f");
const SEV = { CRITICAL: 20, HIGH: 12, MEDIUM: 6, LOW: 3, UNKNOWN: 5 }, ORDER = ["LOW", "UNKNOWN", "MEDIUM", "HIGH", "CRITICAL"];

async function j(url, ctx, src, opts = {}) {
  try {
    const c = new AbortController(), t = setTimeout(() => c.abort(), 12000);
    const r = await fetch(url, { ...opts, signal: c.signal, headers: { "user-agent": "opensource-iq", ...(opts.headers || {}) } });
    clearTimeout(t);
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json(); ctx.src[src] = "ok"; return d;
  } catch (e) { if (ctx.src[src] !== "ok") ctx.src[src] = "unavailable (" + e.message + ")"; return null; }
}

let kev = null, kevAt = 0;
async function getKev(ctx) {
  if (kev && Date.now() - kevAt < 216e5) { ctx.src["CISA KEV"] = "ok (cached)"; return kev; }
  const d = await j("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", ctx, "CISA KEV");
  if (d) { kev = new Set(d.vulnerabilities.map((v) => v.cveID)); kevAt = Date.now(); }
  return kev || new Set();
}

// 1. COLLECT: dependency tree (depth 2, max 25 packages) from the npm registry
async function collectTree(root, ctx) {
  const nodes = new Map(); let level = [root];
  for (let d = 0; d <= 2 && level.length && nodes.size < 25; d++) {
    const batch = level.filter((n) => !nodes.has(n)).slice(0, 25 - nodes.size);
    const metas = await Promise.all(batch.map((n) => j(`${REG}/${enc(n)}/latest`, ctx, "npm registry")));
    const next = [];
    batch.forEach((n, i) => {
      const m = metas[i];
      if (!m && d === 0) throw Object.assign(new Error(`"${n}" was not found on npm.`), { code: 404 });
      const deps = m ? Object.keys(m.dependencies || {}).slice(0, 8) : [];
      nodes.set(n, { name: n, depth: d, version: m && m.version, deps, repo: m && (m.repository && (m.repository.url || m.repository)), maintainers: m && (m.maintainers || []).length });
      if (d < 2) next.push(...deps);
    });
    level = [...new Set(next)];
  }
  // release dates (small search response); full history only for the root
  await Promise.all([...nodes.values()].map(async (n) => {
    const s = await j(`${REG}/-/v1/search?text=${encodeURIComponent(n.name)}&size=5`, ctx, "npm search");
    const h = s && (s.objects || []).find((o) => o.package.name === n.name);
    if (h) { n.date = h.package.date; if (h.package.maintainers) n.maintainers = h.package.maintainers.length; }
  }));
  const full = await j(`${REG}/${enc(root)}`, ctx, "npm history");
  const r = nodes.get(root);
  if (full && full.time) {
    const ts = Object.entries(full.time).filter(([k]) => /^\d/.test(k)).map(([, v]) => +new Date(v)).sort((a, b) => a - b).slice(-11);
    const gaps = ts.slice(1).map((t, i) => (t - ts[i]) / 864e5).sort((a, b) => a - b);
    r.cadenceDays = gaps.length ? Math.round(gaps[Math.floor(gaps.length / 2)]) : null;
    r.releases = Object.keys(full.time).filter((k) => /^\d/.test(k)).length;
  }
  return nodes;
}

async function collectGithub(node, ctx) {
  const m = node.repo && String(node.repo).match(/github\.com[/:]([^/]+)\/([^/.#]+)/);
  if (!m) { ctx.src["GitHub"] = "skipped (no repository link)"; return null; }
  const d = await j(`https://api.github.com/repos/${m[1]}/${m[2]}`, ctx, "GitHub", GH_TOKEN ? { headers: { authorization: "Bearer " + GH_TOKEN } } : {});
  return d && { repo: `${m[1]}/${m[2]}`, stars: d.stargazers_count, openIssues: d.open_issues_count, pushedAt: d.pushed_at, archived: d.archived };
}

async function collectVulns(nodes, ctx) {
  const list = [...nodes.values()].filter((n) => n.version);
  const res = await j("https://api.osv.dev/v1/querybatch", ctx, "OSV", { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ queries: list.map((n) => ({ package: { name: n.name, ecosystem: "npm" }, version: n.version })) }) });
  const refs = []; // raw records: one per (package, advisory id)
  if (res) res.results.forEach((r, i) => (r.vulns || []).forEach((v) => refs.push({ pkg: list[i].name, id: v.id })));
  const ids = [...new Set(refs.map((r) => r.id))].slice(0, 40), detail = {};
  await Promise.all(ids.map(async (id) => { const d = await j(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, ctx, "OSV"); if (d) detail[id] = d; }));
  const cves = [...new Set(Object.values(detail).flatMap((d) => (d.aliases || []).concat(d.id).filter((a) => /^CVE-/.test(a))))];
  const epss = {};
  if (cves.length) {
    const e = await j("https://api.first.org/data/v1/epss?cve=" + cves.join(","), ctx, "EPSS");
    (e && e.data || []).forEach((x) => (epss[x.cve] = +x.epss));
  }
  return { refs, detail, epss, kev: await getKev(ctx) };
}

// 2. CLEAN: de-duplicate by CVE alias, standardise severity labels, log what changed
function clean(nodes, v) {
  const audit = { rawRecords: v.refs.length, nonStandardSeverity: 0, noRepo: 0 }, canon = new Map(), byPkg = {};
  for (const r of v.refs) {
    const d = v.detail[r.id]; if (!d) continue;
    const raw = ((d.database_specific && d.database_specific.severity) || "").toUpperCase();
    let sev = raw; if (raw === "MODERATE") { sev = "MEDIUM"; audit.nonStandardSeverity++; } else if (!SEV[raw] || raw === "UNKNOWN") { if (raw) audit.nonStandardSeverity++; sev = "UNKNOWN"; }
    const cve = (d.aliases || []).concat(d.id).find((a) => /^CVE-/.test(a)) || null, key = cve || d.id;
    if (!canon.has(key)) canon.set(key, { id: d.id, cve, sev, summary: d.summary || "", epss: cve ? v.epss[cve] ?? null : null, kev: !!(cve && v.kev.has(cve)) });
    (byPkg[r.pkg] = byPkg[r.pkg] || new Set()).add(key);
  }
  nodes.forEach((n) => { if (!n.repo) audit.noRepo++; });
  audit.uniqueRecords = canon.size; audit.duplicatesRemoved = Math.max(0, audit.rawRecords - canon.size - 0);
  audit.missingSeverity = [...canon.values()].filter((c) => c.sev === "UNKNOWN").length;
  return { canon, byPkg, audit };
}

// 3+4. ENGINEER features and SCORE (composite risk index with transitive propagation)
function score(nodes, cl, gh) {
  const memo = new Map(), now = Date.now();
  const calc = (name, seen = new Set()) => {
    if (memo.has(name)) return memo.get(name);
    const n = nodes.get(name); if (seen.has(name)) return 0; seen.add(name);
    const vs = [...(cl.byPkg[name] || [])].map((k) => cl.canon.get(k));
    let vuln = 0; const why = [];
    vs.forEach((x) => { vuln += SEV[x.sev]; if (x.epss > 0.1) { vuln += 5; why.push(`${x.cve} has high exploit likelihood (EPSS ${(x.epss * 100).toFixed(0)}%)`); } if (x.kev) { vuln += 15; why.push(`${x.cve} is on the CISA known-exploited list`); } });
    vuln = Math.min(40, vuln);
    const months = n.date ? (now - new Date(n.date)) / 2629800000 : null; let maint = months === null ? 10 : months < 3 ? 0 : months < 6 ? 5 : months < 12 ? 12 : months < 24 ? 22 : 30;
    if (n.maintainers === 1) maint += 5;
    const g = name === nodes.keys().next().value ? gh : null;
    if (g && g.archived) maint += 10; if (g && now - new Date(g.pushedAt) > 365 * 864e5) maint += 5;
    maint = Math.min(35, maint);
    const kids = n.deps.filter((d) => nodes.has(d)).map((d) => ({ d, t: calc(d, new Set(seen)) })).sort((a, b) => b.t - a.t);
    const prop = kids.length ? Math.min(25, Math.round(kids[0].t * 0.35)) : 0;
    Object.assign(n, { vulnPts: vuln, maintPts: maint, propPts: prop, total: Math.min(100, vuln + maint + prop), months, vulnKeys: vs.map((x) => x.cve || x.id), worstChild: kids[0] && kids[0].t > 0 ? kids[0].d : null, why });
    memo.set(name, n.total); return n.total;
  };
  nodes.forEach((_, k) => calc(k));
}

async function analyze(pkg) {
  const ctx = { src: {} }, nodes = await collectTree(pkg, ctx), root = nodes.get(pkg);
  const [gh, v] = await Promise.all([collectGithub(root, ctx), collectVulns(nodes, ctx)]);
  const cl = clean(nodes, v); score(nodes, cl, gh);
  const ex = [];
  ex.push({ factor: "Known vulnerabilities", points: root.vulnPts, detail: root.vulnKeys.length ? `${root.vulnKeys.length} unique advisories on ${root.version}` : `none found for ${root.version}` });
  root.why.forEach((w) => ex.push({ factor: "Exploit signal", points: 0, detail: w }));
  ex.push({ factor: "Maintenance", points: root.maintPts, detail: `${root.months === null ? "release date unknown" : "last release " + Math.round(root.months) + " months ago"}${root.maintainers === 1 ? ", single maintainer" : root.maintainers ? ", " + root.maintainers + " maintainers" : ""}${root.cadenceDays ? `, median gap between releases ${root.cadenceDays} days` : ""}${gh && gh.archived ? ", repository archived" : ""}` });
  ex.push({ factor: "Propagated from dependencies", points: root.propPts, detail: root.worstChild ? `riskiest dependency: ${root.worstChild} (score ${nodes.get(root.worstChild).total})` : "no risky dependencies found" });
  // Prototype predictive layer: logistic form with hand-set weights (placeholder for a trained XGBoost model)
  const z = -3.2 + 0.05 * root.total + 0.03 * Math.min(root.months ?? 12, 48) + (root.maintainers === 1 ? 0.6 : 0);
  return { name: pkg, sources: ctx.src, audit: cl.audit, github: gh, explain: ex, predicted: +(1 / (1 + Math.exp(-z))).toFixed(3),
    vulns: [...(cl.byPkg[pkg] || [])].map((k) => cl.canon.get(k)),
    nodes: [...nodes.values()].map(({ name, version, depth, deps, total, vulnPts, maintPts, propPts, vulnKeys }) => ({ name, version, depth, deps: deps.filter((d) => nodes.has(d)), total, vulnPts, maintPts, propPts, vulnCount: vulnKeys.length })) };
}

http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  if (u.pathname === "/api/analyze") {
    const pkg = (u.searchParams.get("pkg") || "").trim().toLowerCase(), send = (c, o) => { res.writeHead(c, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
    if (!/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(pkg)) return send(400, { error: "Enter a valid npm package name." });
    try { send(200, await analyze(pkg)); } catch (e) { send(e.code === 404 ? 404 : 500, { error: e.message }); }
    return;
  }
  const f = path.join(__dirname, "public", u.pathname === "/" ? "index.html" : path.normalize(u.pathname).replace(/^(\.\.[/\\])+/, ""));
  fs.readFile(f, (err, data) => { if (err) { res.writeHead(404); return res.end("Not found"); } res.writeHead(200, { "content-type": f.endsWith(".html") ? "text/html" : "text/plain" }); res.end(data); });
}).listen(PORT, () => console.log("OpenSource IQ on http://localhost:" + PORT));
