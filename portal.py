"""Vigil web portal. Listens on this laptop only."""
import collections, hashlib, hmac, logging, os, pathlib, subprocess, tempfile, time
from datetime import datetime
import uvicorn
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
import db, report
from process_tree import build_tree

BASE = pathlib.Path(__file__).parent
HOST, PORT = "127.0.0.1", 8080
PUBLIC = os.environ.get("VIGIL_PUBLIC") == "1"  # served over HTTPS through the tunnel
PASSWORD_HASH = os.environ["VIGIL_PORTAL_HASH"]
SESSION_SECRET = os.environ["VIGIL_SESSION_SECRET"]
SESSION_SECONDS = 8 * 3600
MAX_FAILURES, FAILURE_WINDOW = 5, 900
OPEN_PATHS = ("/login", "/static/")
DECISIONS = {"approved", "rejected", "closed", "reopened"}
MAX_NOTE = 1000
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

logging.basicConfig(filename=BASE / "data" / "portal.log", encoding="utf-8", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Vigil MDR", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")


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


def filtered(incidents, status, verdict):
    return [i for i in incidents
            if (not status or i["status"] == status)
            and (not verdict or i["analysis"].get("verdict", "none") == verdict)]


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
def dashboard(request: Request, status: str = "", verdict: str = ""):
    incidents = db.load_incidents()
    stats = {
        "open": sum(i["status"] == "open" for i in incidents),
        "high": sum(i["status"] == "open" and i["score"] >= 70 for i in incidents),
        "total": len(incidents),
        "detections": sum(len(i["detect_ids"]) for i in incidents),
    }
    return templates.TemplateResponse(request, "dashboard.html", {
        "stats": stats, "incidents": filtered(incidents, status, verdict), "status": status, "verdict": verdict})


@app.get("/incidents/table", response_class=HTMLResponse)
def incident_table(request: Request, status: str = "", verdict: str = ""):
    return templates.TemplateResponse(request, "_table.html", {
        "incidents": filtered(db.load_incidents(), status, verdict)})


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_page(request: Request, incident_id: str):
    incident = get_incident(incident_id)
    detail = db.load_incident_detail(incident_id)
    return templates.TemplateResponse(request, "incident.html", {
        "incident": incident, "detail": detail, "files": file_indicators(detail["detections"]),
        "tree": build_tree(detail["detections"])})


@app.post("/incidents/{incident_id}/review", response_class=HTMLResponse, dependencies=[Depends(same_origin)])
def review(request: Request, incident_id: str, decision: str = Form(...), note: str = Form("")):
    if decision not in DECISIONS:
        raise HTTPException(status_code=400)
    incident = get_incident(incident_id)
    db.save_review(incident_id, decision, note.strip()[:MAX_NOTE], incident["detect_ids"])
    return templates.TemplateResponse(request, "_review.html", {
        "incident": get_incident(incident_id), "detail": db.load_incident_detail(incident_id)})


def report_html():
    incidents = db.load_incidents()
    return report.build(report.load_cases(incidents), incidents)


@app.get("/report", response_class=HTMLResponse)
def html_report():
    return report_html()


@app.get("/report.pdf")
def pdf_report():
    report.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    target = report.REPORT_DIR / f"vigil-report-{datetime.now():%Y%m%d-%H%M%S}.pdf"
    with tempfile.TemporaryDirectory() as folder:
        source = pathlib.Path(folder) / "report.html"
        source.write_text(report_html(), encoding="utf-8")
        subprocess.run([EDGE, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                        f"--print-to-pdf={target}", source.as_uri()], timeout=60, check=False)
    if not target.exists():
        raise HTTPException(status_code=500, detail="PDF could not be created")
    return FileResponse(target, media_type="application/pdf", filename=target.name)


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT, log_config=None)
