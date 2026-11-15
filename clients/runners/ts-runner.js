// Runs a batch of calls through one generated TypeScript client (openapi-generator typescript-axios,
// built to dist/ with useSingleRequestParameter=true).
//
// Usage: node ts-runner.js <client dir> <base url> <calls.json> <out.json>
// calls.json: [{"id", "operationId", "params": {spec name: value}, "specNames": [...], "body": json or null,
//               "hasParams": bool, "auth": "<Authorization header>", "headers": {name: value}}]
// A params value {"__file__": name, "content", "type"} is a file part, sent as a File with that name.
// The body goes under the request-object key the method reads that is not a spec parameter.
// out.json:   [{"id", "status", "headers", "body", "client_error"}]
//
// typescript-axios checks types only at compile time, so at run time the client accepts any body; the
// suite's own checks judge the answer it hands back.
const fs = require('fs');
const { File } = require('buffer');
const path = require('path');

const [, , clientDir, base, callsFile, outFile] = process.argv;
const lib = require(path.resolve(clientDir, 'dist', 'index.js'));
const norm = (s) => s.replace(/[^A-Za-z0-9]/g, '').toLowerCase();
// The generator's request-object keys are the parameter names in camelCase.
const camel = (s) => s.replace(/[-_ ]+([A-Za-z0-9])/g, (_, c) => c.toUpperCase());
const apis = Object.entries(lib).filter(([n, v]) => n.endsWith('Api') && typeof v === 'function');

function answer(c, r, clientError) {
  const headers = {};
  for (const [k, v] of Object.entries(r.headers || {})) headers[k] = Array.isArray(v) ? v.join(', ') : String(v);
  const body = typeof r.data === 'string' ? r.data : r.data === undefined ? '' : JSON.stringify(r.data);
  return { id: c.id, status: r.status, headers, body, client_error: clientError };
}

async function run(c) {
  let target = null;
  for (const [, Cls] of apis) {
    const name = Object.getOwnPropertyNames(Cls.prototype).find((m) => norm(m) === norm(c.operationId));
    if (name) { target = [Cls, name]; break; }
  }
  if (!target) return { id: c.id, status: null, headers: {}, body: '', client_error: `operationId ${c.operationId} not found in generated client` };
  const api = new target[0](new lib.Configuration({ basePath: base, baseOptions: { headers: { Authorization: c.auth, ...(c.headers || {}) } } }));
  const asFile = (v) => (v && typeof v === 'object' && v.__file__ ? new File([v.content], v.__file__, { type: v.type || 'application/octet-stream' }) : v);
  const params = Object.fromEntries(Object.entries(c.params).map(([k, v]) => [camel(k), Array.isArray(v) ? v.map(asFile) : asFile(v)]));
  if (c.body !== null && c.body !== undefined) {
    // The compiled method reads requestParameters.<key>; the body's key is the one that is no spec parameter.
    const keys = [...api[target[1]].toString().matchAll(/requestParameters\.(\w+)/g)].map((m) => m[1]);
    const spec = new Set((c.specNames || []).map((n) => norm(camel(n))));
    const key = keys.find((k) => !spec.has(norm(k)));
    if (!key) return { id: c.id, status: null, headers: {}, body: '', client_error: 'the generated method takes no request body' };
    params[key] = c.body;
  }
  try {
    const r = c.hasParams ? await api[target[1]](params) : await api[target[1]]();
    return answer(c, r, null);
  } catch (e) {
    if (e.response) return answer(c, e.response, null); // a non-2xx answer, reported by the client
    return { id: c.id, status: null, headers: {}, body: '', client_error: `${e.name}: ${e.message}` };
  }
}

(async () => {
  const out = [];
  for (const c of JSON.parse(fs.readFileSync(callsFile, 'utf8'))) out.push(await run(c));
  fs.writeFileSync(outFile, JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
