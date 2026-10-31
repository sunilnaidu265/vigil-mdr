"""Vigil web portal. Listens on this laptop only."""
import collections, hashlib, hmac, logging, os, pathlib, subprocess, tempfile, time
from datetime import datetime, timezone
import psycopg, requests, uvicorn
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
import charts, db, report
from process_tree import build_tree

BASE = pathlib.Path(__file__).parent
HOST, PORT = "127.0.0.1", 8080
PUBLIC = os.environ.get("VIGIL_PUBLIC") == "1"  # served over HTTPS through the tunnel
PASSWORD_HASH = os.environ["VIGIL_PORTAL_HASH"]
SESSION_SECRET = os.environ["VIGIL_SESSION_SECRET"]
SESSION_SECONDS = 8 * 3600
MAX_FAILURES, FAILURE_WINDOW = 5, 900
OPEN_PATHS = ("/login", "/static/")
DECISIONS = {"in_review", "approved", "rejected", "closed", "reopened"}
REJECT_REASONS = {"false_positive": "False positive", "wrong_facts": "Wrong facts", "missing_context": "Missing context"}
CUSTOMER_READY = {"approved", "edited"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
MAX_NOTE = 1000
MAX_SUMMARY = 4000
OLLAMA_TAGS = "http://localhost:11434/api/tags"
EDGE =r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

logging.basicConfig(filename=BASE / "data" / "portal.log", encoding="utf-8", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Vigil MDR", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")


def age_text(when):
    seconds = int((datetime.now(timezone.utc) - when).total_seconds())
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "min")):
        if seconds >= size:
            count = seconds // size
            return f"{count} {unit}{'s' if count > 1 and unit != 'min' else ''} ago"
    return "just now"


def mitre_url(technique):
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def duration_text(seconds):
    if seconds is None:
        return "No data yet"
    seconds = float(seconds)
    if seconds < 90:
        return f"{seconds:.0f} sec"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} hours"


templates.env.filters.update(age=age_text, mitre_url=mitre_url, duration=duration_text)
templates.env.globals["reject_reasons"] = REJECT_REASONS


@app.exception_handler(psycopg.OperationalError)
def database_offline(request, error):
    logging.error("database unavailable: %s", error)
    return templates.TemplateResponse(request, "error.html", {
        "title": "Database offline", "message": "PostgreSQL isn't reachable, so incidents can't be shown right now."},
        status_code=503)


failures = collections.defaultdict(list)


@app.middleware("http")
async def require_login(request, call_next):
    if request.url.path.startswith(OPEN_PATHS) or request.session.get("user"):
        return await call_next(request)
    if request.headers.get("hx-request"):  # the 30-second refresh must not swap in a login page
        return Response(headers={"HX-Redirect": "/login"})
    return RedirectResponse("/login", status_code=303)


app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, session_cookie="vigil_session",
                   max_age=SESSION_SECONDS, same_site="strict", https_only=PUBLIC)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "*.trycloudflare.com"])


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def same_origin(request: Request):
    # stops another website in the browser from submitting a form
    host = request.headers.get("host")
    allowed = {f"https://{host}"} if PUBLIC else {f"http://{host}"}
    if request.headers.get("origin") not in allowed:
        raise HTTPException(status_code=403)


def password_ok(password):
    salt, expected = PASSWORD_HASH.split("$")
    actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    return hmac.compare_digest(actual.hex(), expected)


def client_ip(request):
    return request.headers.get("cf-connecting-ip") or request.client.host


def locked_out(ip):
    recent = [t for t in failures[ip] if time.time() - t < FAILURE_WINDOW]
    failures[ip] = recent
    return len(recent) >= MAX_FAILURES


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if request.session.get("user"):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": ""})


@app.post("/login", response_class=HTMLResponse, dependencies=[Depends(same_origin)])
def login(request: Request, password: str = Form(...)):
    ip = client_ip(request)
    if locked_out(ip):
        return templates.TemplateResponse(request, "login.html", {"error": "Too many attempts. Try again later."},
                                          status_code=429)
    if not password_ok(password):
        failures[ip].append(time.time())
        logging.warning("failed login from %s", ip)
        return templates.TemplateResponse(request, "login.html", {"error": "Wrong password."}, status_code=401)
    failures.pop(ip, None)
    request.session["user"] = "analyst"
    return RedirectResponse("/", status_code=303)


@app.post("/logout", dependencies=[Depends(same_origin)])
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


def severity_of(incident):
    return incident["analysis"].get("severity") or "unrated"


def queue(incidents, status="", severity="", host="", verdict=""):
    chosen = [i for i in incidents
              if (not status or i["status"] == status)
              and (not severity or severity_of(i) == severity)
              and (not host or i["host"] == host)
              and (not verdict or i["analysis"].get("verdict", "none") == verdict)]
    chosen.sort(key=lambda i: i["started_at"], reverse=True)  # newest first within a severity
    return sorted(chosen, key=lambda i: SEVERITY_ORDER.get(severity_of(i), len(SEVERITY_ORDER)))


def ollama_online():
    try:
        return requests.get(OLLAMA_TAGS, timeout=1).ok
    except requests.RequestException:
        return False


def chain_steps(analysis, events):
    times = {e["event_id"]: e["event_time"] for e in events}
    steps = []
    for step in (analysis or {}).get("attack_chain") or []:
        seen = [times[i] for i in step.get("event_ids", []) if times.get(i)]
        steps.append({**step, "time": min(seen) if seen else None})
    # the model doesn't always keep time order, and untimed steps go last
    return sorted(steps, key=lambda s: (s["time"] is None, s["time"] or datetime.min.replace(tzinfo=timezone.utc)))


def get_incident(incident_id):
    incident = next((i for i in db.load_incidents() if i["incident_id"] == incident_id), None)
    if incident is None:
        raise HTTPException(status_code=404)
    return incident


def file_indicators(detections):
    files = collections.Counter()
    for det in detections:
        for node in report.walk_dicts(det["raw"].get("detect") or {}):
            if node.get("FILE_PATH"):
                files[(node["FILE_PATH"], node.get("HASH") or "")] += 1
    return [{"path": k[0], "hash": k[1], "count": v} for k, v in files.most_common()]


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, status: str = "", severity: str = "", host: str = "", verdict: str = ""):
    incidents = db.load_incidents()
    stats = {
        "open": sum(i["status"] in ("open", "in_review") for i in incidents),
        "urgent": sum(i["status"] in ("open", "in_review") and severity_of(i) in ("critical", "high") for i in incidents),
        "failed": sum(i["ai_status"] == "failed" for i in incidents),
        "detections": sum(len(i["detect_ids"]) for i in incidents),
    }
    return templates.TemplateResponse(request, "dashboard.html", {
        "stats": stats, "incidents": queue(incidents, status, severity, host, verdict), "status": status,
        "severity": severity, "host": host, "verdict": verdict, "hosts": sorted({i["host"] for i in incidents}),
        "ollama_online": ollama_online()})


@app.get("/incidents/table", response_class=HTMLResponse)
def incident_table(request: Request, status: str = "", severity: str = "", host: str = "", verdict: str = ""):
    return templates.TemplateResponse(request, "_table.html", {
        "incidents": queue(db.load_incidents(), status, severity, host, verdict)})


@app.get("/metrics", response_class=HTMLResponse)
def metrics_page(request: Request):
    metrics = db.load_metrics()
    days = collections.defaultdict(collections.Counter)
    for row in metrics["per_day"]:
        days[row["day"]][row["severity"]] += row["total"]
    decided = {row["decision"]: row["total"] for row in metrics["decisions"]}
    incidents = db.load_incidents()
    severities = collections.Counter(severity_of(i) for i in incidents)
    verdicts = collections.Counter(i["analysis"].get("verdict") for i in incidents)
    timeline = charts.time_series(metrics["times"])
    return templates.TemplateResponse(request, "metrics.html", {
        "metrics": metrics, "days": dict(days), "decided": decided, "decided_total": sum(decided.values()),
        "timeline": timeline,
        "timeline_chart": charts.column_chart(timeline, "Detections over time"),
        "rules_chart": charts.ranked_bars([(r["rule"], r["total"]) for r in metrics["rules"][:8]]),
        "techniques_chart": charts.ranked_bars([(t["technique"], t["total"]) for t in metrics["techniques"][:8]]),
        "severity_chart": charts.segmented_bar([(s, severities[s]) for s in charts.SEVERITY_ORDER], "Incidents by severity", "sev"),
        "verdict_chart": charts.segmented_bar([(v, verdicts[v]) for v in charts.VERDICT_ORDER], "AI verdicts", "verdict"),
        "heatmap_chart": charts.heatmap(metrics["times"])})


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_page(request: Request, incident_id: str):
    incident = get_incident(incident_id)
    detail = db.load_incident_detail(incident_id)
    latest = detail["analyses"][0] if detail["analyses"] else None
    return templates.TemplateResponse(request, "incident.html", {
        "incident": incident, "detail": detail, "latest": latest, "chain": chain_steps(latest, detail["events"]),
        "event_ids": {e["event_id"] for e in detail["events"]}, "files": file_indicators(detail["detections"]),
        "tree": build_tree(detail["detections"]), "customer_ready": incident["status"] in CUSTOMER_READY})


def back_to(incident_id):
    return RedirectResponse(f"/incidents/{incident_id}", status_code=303)


@app.post("/incidents/{incident_id}/review", dependencies=[Depends(same_origin)])
def review(incident_id: str, decision: str = Form(...), note: str = Form(""), reason: str = Form("")):
    if decision not in DECISIONS or (decision == "rejected" and reason not in REJECT_REASONS):
        raise HTTPException(status_code=400)
    incident = get_incident(incident_id)
    db.save_review(incident_id, decision, note.strip()[:MAX_NOTE], incident["detect_ids"],
                   reason if decision == "rejected" else "")
    return back_to(incident_id)


@app.post("/incidents/{incident_id}/edit", dependencies=[Depends(same_origin)])
def edit_summary(incident_id: str, summary: str = Form(...), note: str = Form("")):
    incident = get_incident(incident_id)
    before = incident["analysis"].get("summary")
    after = summary.strip()[:MAX_SUMMARY]
    if not before or not after:
        raise HTTPException(status_code=400)
    if after != before:
        db.save_review(incident_id, "edited", note.strip()[:MAX_NOTE], incident["detect_ids"], before=before, after=after)
    return back_to(incident_id)


def customer_context(incident_id):
    incident = get_incident(incident_id)
    detail = db.load_incident_detail(incident_id)
    latest = detail["analyses"][0] if detail["analyses"] else None
    ready = incident["status"] in CUSTOMER_READY and latest is not None
    return {"incident": incident, "latest": latest, "chain": chain_steps(latest, detail["events"]), "ready": ready}


@app.get("/incidents/{incident_id}/customer", response_class=HTMLResponse)
def customer_report(request: Request, incident_id: str):
    context = customer_context(incident_id)
    return templates.TemplateResponse(request, "customer.html", context, status_code=200 if context["ready"] else 409)


def pdf_response(html_text, name):
    report.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    target = report.REPORT_DIR / f"{name}-{datetime.now():%Y%m%d-%H%M%S}.pdf"
    with tempfile.TemporaryDirectory() as folder:
        source = pathlib.Path(folder) / "report.html"
        source.write_text(html_text, encoding="utf-8")
        subprocess.run([EDGE, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                        f"--print-to-pdf={target}", source.as_uri()], timeout=60, check=False)
    if not target.exists():
        raise HTTPException(status_code=500, detail="PDF could not be created")
    return FileResponse(target, media_type="application/pdf", filename=target.name)


@app.get("/incidents/{incident_id}/customer.pdf")
def customer_pdf(request: Request, incident_id: str):
    context = customer_context(incident_id)
    if not context["ready"]:
        raise HTTPException(status_code=409, detail="Approve or edit this incident first")
    html_text = templates.get_template("customer.html").render({"request": request, **context})
    return pdf_response(html_text, f"vigil-customer-{incident_id}")


def report_html():
    incidents = db.load_incidents()
    return report.build(report.load_cases(incidents), incidents)


@app.get("/report", response_class=HTMLResponse)
def html_report():
    return report_html()


@app.get("/report.pdf")
def pdf_report():
    return pdf_response(report_html(), "vigil-report")


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT, log_config=None)
