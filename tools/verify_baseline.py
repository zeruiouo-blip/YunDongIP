from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
main = (ROOT / 'cmd' / 'yundongip' / 'main.go').read_text(encoding='utf-8')
go_mod = (ROOT / 'go.mod').read_text(encoding='utf-8')
html_path = ROOT / 'cmd' / 'yundongip' / 'index.html'
html = html_path.read_text(encoding='utf-8')

checks = {
    'responsive viewport': 'applyResponsiveViewport' in html,
    'staged precision board': 'stagePrecisionBatch' in html and 'TEST_RENDER_BATCH' in html,
    'indexed trace merge': 'scanIndexMap' in html,
    'scan x4': 'scanProbeCount     = 4' in main,
    'loss cutoff 60%': 'scanLossCutoff     = 0.60' in main,
    'scan timeout 1s': 'scanDialTimeout    = 1 * time.Second' in main,
    'batch 50': 'scanBatchSize      = 50' in main and 'scanTraceBatchSize = 50' in main,
    'trace workers 64': 'scanTraceWorkers   = 64' in main,
    'scan_batch': 'scan_batch' in main,
    'scan_trace_batch': 'scan_trace_batch' in main,
    'task_complete': 'task_complete' in main,
    'clean scan implementation present': 'func startScanSession(' in main and 'func performProbeSeries(' in main and 'func resolveCFTrace(' in main,
    'project WebSocket implementation present': 'func upgradeWebSocket(' in main and 'type wsConn struct' in main,
    'no external Go modules': 'require ' not in go_mod and 'replace ' not in go_mod,
    'no github.com imports': 'github.com/' not in '\n'.join(line for line in main.splitlines() if line.strip().startswith('\"github.com/')),
    'old scan helper names absent': not re.search(r'^func (probeCloudflareIP4|traceCloudflareColo|getRandomIPv4s|getRandomIPv6s)\(', main, re.M),
    'project provenance marker': 'YDI-PROVENANCE-0.1.1-A73D91F4' in main and 'YDI-PROVENANCE-0.1.1-A73D91F4' in html,
    'about endpoint': 'http.HandleFunc("/api/about", handleAbout)' in main,
    'build metadata variables': 'buildVersion' in main and 'buildCommit' in main,
    'runtime state ignored': 'yundongip-*.json' in (ROOT / '.gitignore').read_text(encoding='utf-8'),
}

failed = [name for name, ok in checks.items() if not ok]
for name, ok in checks.items():
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
if failed:
    raise SystemExit('baseline verification failed')
