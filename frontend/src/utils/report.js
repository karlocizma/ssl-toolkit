// Export helpers: a result as JSON or as a self-contained, print-friendly HTML report.
// Everything that ends up in the HTML is escaped; the report has no scripts and no external resources.

export const escapeHtml = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const isScalar = (v) => ['string', 'number', 'boolean'].includes(typeof v);

export const topFacts = (result) =>
  Object.entries(result && typeof result === 'object' && !Array.isArray(result) ? result : {})
    .filter(([, v]) => isScalar(v))
    .slice(0, 30);

export const findingsOf = (result) =>
  Array.isArray(result?.findings)
    ? result.findings.map((f) => (typeof f === 'string' ? { message: f } : f)).filter((f) => f && typeof f === 'object')
    : [];

export function buildHtmlReport({ title, tool, generatedAt, result }) {
  const facts = topFacts(result);
  const findings = findingsOf(result);
  const rows = facts.map(([k, v]) => `<tr><th>${escapeHtml(k)}</th><td>${escapeHtml(v)}</td></tr>`).join('');
  const frows = findings
    .map((f) => `<tr><td class="sev ${escapeHtml(f.severity || 'info')}">${escapeHtml(f.severity || 'info')}</td><td>${escapeHtml(f.message || f.title || JSON.stringify(f))}</td></tr>`)
    .join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>${escapeHtml(title)}</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:900px;padding:0 1rem;color:#1b1f23}
h1{font-size:1.5rem;margin-bottom:.2rem}.meta{color:#57606a;margin-bottom:1.5rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}th,td{border:1px solid #d0d7de;padding:.35rem .6rem;text-align:left;vertical-align:top}
th{background:#f6f8fa;width:30%}.sev{font-weight:600;text-transform:uppercase;width:7rem}
.critical,.error{color:#cf222e}.warning{color:#9a6700}.info{color:#0969da}
pre{background:#f6f8fa;border:1px solid #d0d7de;padding:1rem;overflow:auto;white-space:pre-wrap;word-break:break-word}
@media print{body{margin:0}pre{white-space:pre-wrap}}
</style></head><body>
<h1>${escapeHtml(title)}</h1>
<div class="meta">${escapeHtml(tool)} &middot; generated ${escapeHtml(generatedAt)} by SSL Toolkit</div>
${rows ? `<h2>Summary</h2><table>${rows}</table>` : ''}
${frows ? `<h2>Findings</h2><table>${frows}</table>` : ''}
<h2>Full result</h2><pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>
</body></html>`;
}

export function download(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export const safeName = (s) => String(s || 'result').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'result';

export function exportJson(title, result) {
  download(`${safeName(title)}.json`, JSON.stringify(result, null, 2), 'application/json');
}

export function exportHtml({ title, tool, result }) {
  download(`${safeName(title)}.html`, buildHtmlReport({ title, tool, generatedAt: new Date().toISOString(), result }), 'text/html');
}
