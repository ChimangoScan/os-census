#!/usr/bin/env python3
"""Dashboard ao vivo do censo de imagens de SO. Tema ChimangoScan (report_lab).
stdlib only. Lê work/os.db (jobs + reports). Rodar:  python3 scripts/dashboard.py [porta]
"""
import json, sqlite3, sys, shutil, time, glob, threading, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = Path(os.environ.get("OSCENSUS_DB") or ROOT / "work/os.db")
_legacy = Path("/mnt/win_ssd/scanners-data/out_so")
OUT = Path(os.environ.get("OSCENSUS_OUT") or (_legacy if _legacy.exists() else ROOT/"scan-out"/"out_so"))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8911

def q(db, sql, args=()):
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)
    try: return c.execute(sql, args).fetchall()
    finally: c.close()

def repo_of(tj):
    try:
        d = json.loads(tj); return (d.get("meta") or {}).get("repo") or d.get("repo") or "?"
    except Exception: return "?"

_REPO = {}   # name -> repo, estático: construído uma vez (evita parsear blobs por request)
def repo_map():
    if not _REPO:
        for name, tj in q(DB, "SELECT name,target_json FROM jobs"):
            _REPO[name] = repo_of(tj)
    return _REPO

def snapshot():
    s = {r[0]: r[1] for r in q(DB, "SELECT status,count(*) FROM jobs GROUP BY status")}
    total = sum(s.values()); done = s.get("done", 0)
    findings = q(DB, "SELECT COALESCE(SUM(n_findings),0), COUNT(*) FROM reports")[0]
    rm = repo_map()
    per = {}
    for name, st in q(DB, "SELECT name,status FROM jobs"):   # leve: sem blobs
        r = rm.get(name, "?"); d = per.setdefault(r, [0, 0, 0]); d[2] += 1   # [done, skip, total]
        if st == "done": d[0] += 1
        elif st == "skipped": d[1] += 1
    recent = q(DB, "SELECT name,finished_at FROM jobs WHERE status='done' AND finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 14")
    failed = q(DB, "SELECT name,error FROM jobs WHERE status='failed' ORDER BY finished_at DESC LIMIT 8")
    running = q(DB, "SELECT name FROM jobs WHERE status='running' ORDER BY started_at LIMIT 10")
    try: duw = shutil.disk_usage(str(OUT) if OUT.exists() else str(ROOT))
    except Exception: duw = shutil.disk_usage("/")
    try: dud = shutil.disk_usage("/var/lib/docker")
    except Exception: dud = duw
    out_sz = len(glob.glob(str(OUT / "*/report.json"))) if OUT.exists() else 0  # nº imgs c/ report (barato)
    # ETA + taxa (img/min) + buckets de 1h
    now = time.time()
    fa = [r[0] for r in q(DB, "SELECT finished_at FROM jobs WHERE status='done' AND finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 60")]
    rate = (len(fa)-1)/(fa[0]-fa[-1]) if len(fa) > 5 and fa[0] > fa[-1] else 0   # imgs/s
    eta = (s.get("pending",0)+s.get("running",0))/rate if rate else 0
    permin = q(DB, "SELECT count(*) FROM jobs WHERE finished_at > ?", (now-600,))[0][0] / 10.0
    nb = 14; buckets = [0]*nb   # buckets[0]=hora atual ... buckets[nb-1]=13h atras
    for (ts,) in q(DB, "SELECT finished_at FROM jobs WHERE finished_at IS NOT NULL"):
        h = int((now - ts) // 3600)
        if 0 <= h < nb: buckets[h] += 1
    return dict(s=s, total=total, done=done, findings=findings, per=per, recent=recent,
                failed=failed, running=running, duw=duw, dud=dud, out_sz=out_sz, eta=eta,
                permin=permin, buckets=buckets)

def gb(n): return f"{n/1024**3:.1f} GB"
def hms(s):
    if not s: return "—"
    h = int(s//3600); return f"{h//24}d{h%24}h" if h >= 24 else f"{h}h{int((s%3600)//60)}m"

def page():
    d = snapshot(); pct = 100*d["done"]/d["total"] if d["total"] else 0
    _mx = max(d["buckets"]) or 1
    hist = "".join(f"<div class=b title='{c} imgs ({h}h atras)' style='height:{100*c/_mx:.0f}%'></div>"
                   for h, c in reversed(list(enumerate(d["buckets"]))))
    rep = "".join(
        f"<tr><td>{r}</td><td style='text-align:right'>{v[0]}<span class=t>+{v[1]}sk</span>/{v[2]}</td>"
        f"<td><div class=bar><div style='width:{100*(v[0]+v[1])/v[2] if v[2] else 0:.0f}%'></div></div></td></tr>"
        for r, v in sorted(d["per"].items(), key=lambda x: -(x[1][0]+x[1][1])))
    rec = "".join(f"<li><span class=ok>●</span> {n} <span class=t>{time.strftime('%H:%M:%S', time.localtime(fa))}</span></li>" for n, fa in d["recent"])
    run = "".join(f"<li><span class=rn>●</span> {n}</li>" for (n,) in d["running"]) or "<li class=t>—</li>"
    fail = "".join(f"<li><span class=er>●</span> {n} <span class=t>{(e or '')[:70]}</span></li>" for n, e in d["failed"]) or "<li class=t>nenhuma falha 🎉</li>"
    return f"""<!doctype html><html lang=pt-BR><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><meta http-equiv=refresh content=15>
<title>Censo SO · Docker Hub</title><style>
*{{box-sizing:border-box}}:root{{--bg:#f6f7f9;--fg:#1e293b;--mut:#64748b;--line:#e2e8f0;--card:#fff;--accent:#0f766e;--dark:#0b1220}}
body{{font:14.5px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;margin:0;color:var(--fg);background:var(--bg)}}
header.top{{background:var(--dark);color:#e2e8f0;padding:24px 26px}}
header.top h1{{margin:0;font-size:21px;font-weight:650;letter-spacing:-.01em}}
header.top .sub{{color:#94a3b8;font-size:13px;margin-top:6px}}header.top code{{color:#5eead4}}
main{{max-width:1180px;margin:0 auto;padding:20px 22px 60px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:0 0 18px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}}
.card .v{{font-size:25px;font-weight:680;letter-spacing:-.02em;color:var(--accent)}}
.card .l{{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em;margin-top:3px}}
.card .s{{font-size:11.5px;color:var(--mut);margin-top:5px}}
.pbar{{background:#e2e8f0;border-radius:8px;height:18px;overflow:hidden;margin:4px 0 20px}}.pbar>div{{background:linear-gradient(90deg,#0f766e,#14b8a6);height:18px;transition:width .4s}}
.grid{{display:grid;grid-template-columns:1.5fr 1fr 1fr;gap:14px}}@media(max-width:900px){{.grid{{grid-template-columns:1fr}}}}
.panel{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}}
.panel h3{{margin:0 0 10px;font-size:13px;font-weight:650;text-transform:uppercase;letter-spacing:.04em;color:#334155}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td{{padding:4px 6px;border-bottom:1px solid #f1f5f9}}
.bar{{background:#eef2f4;border-radius:5px;height:8px;width:100%;min-width:80px;overflow:hidden}}.bar>div{{background:#14b8a6;height:8px}}
.hist{{display:flex;align-items:flex-end;gap:3px;height:78px;margin-top:4px}}.hist .b{{flex:1;background:linear-gradient(180deg,#14b8a6,#0f766e);border-radius:2px 2px 0 0;min-height:1px}}
ul{{list-style:none;padding:0;margin:0;max-height:300px;overflow:auto;font-size:13px}}li{{padding:3px 0}}
.t{{color:var(--mut);font-size:12px}}.ok{{color:#10b981}}.rn{{color:#f59e0b}}.er{{color:#ef4444}}
</style></head><body>
<header class=top><h1>🐳 Censo Multi-Scanner — Imagens de Sistema Operacional do Docker Hub</h1>
<div class=sub>20 repos · 5.606 imagens amd64 únicas · 14 scanners estáticos · <code>scansso.anonshield.org</code></div></header>
<main>
<div class=pbar><div style='width:{pct:.1f}%'></div></div>
<div class=cards>
 <div class=card><div class=v>{d['done']:,}/{d['total']:,}</div><div class=l>progresso</div><div class=s>{pct:.1f}% · ETA ~{hms(d['eta'])}</div></div>
 <div class=card><div class=v>{d['s'].get('running',0)} · {d['s'].get('pending',0):,} · {d['s'].get('failed',0)}</div><div class=l>running · pending · failed</div></div>
 <div class=card><div class=v>{d['findings'][0]:,}</div><div class=l>findings totais</div><div class=s>{d['findings'][1]:,} imagens com report</div></div>
 <div class=card><div class=v>{d['permin']:.1f}</div><div class=l>imagens / min</div><div class=s>média dos últimos 10 min</div></div>
 <div class=card><div class=v>{d['out_sz']:,}</div><div class=l>imagens c/ report salvo</div><div class=s>win_ssd livre {gb(d['duw'].free)} · docker {gb(d['dud'].used)}</div></div>
</div>
<div class=panel style=margin-bottom:14px><h3>Concluídas por hora (buckets de 1h, últimas 14h)</h3>
<div class=hist>{hist}</div>
<div class=t>← 13h atrás · hora atual →</div></div>
<div class=grid>
 <div class=panel><h3>Cobertura por repo — done<span class=t>+skip</span>/total (round-robin balanceia por processadas)</h3><table>{rep}</table></div>
 <div class=panel><h3>Concluídas recentes</h3><ul>{rec}</ul></div>
 <div class=panel><h3>Em execução</h3><ul>{run}</ul><h3 style=margin-top:14px>Falhas</h3><ul>{fail}</ul></div>
</div>
<p class=t>auto-refresh 15s · gerado {time.strftime('%Y-%m-%d %H:%M:%S')}</p></main></body></html>"""

_HTML = "<!doctype html><meta http-equiv=refresh content=5><body style='font:14px system-ui'>carregando…</body>"
def _refresh():   # recalcula fora do caminho do request -> requests nunca bloqueiam no DB
    global _HTML
    while True:
        try: _HTML = page()
        except Exception as e: _HTML = f"<pre>erro: {e}</pre>"
        time.sleep(8)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        body = _HTML.encode()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers(); self.wfile.write(body)

if __name__ == "__main__":
    print(f"dashboard em http://localhost:{PORT}")
    threading.Thread(target=_refresh, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
