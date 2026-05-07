"""FastAPI web dashboard for SOC-Swiss-Knife."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Form, Request, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ssk.modules import hash_check, ioc, log_analyser
from ssk.models import Verdict, Severity

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Expose enums to templates
_EXTRA = {"Verdict": Verdict, "Severity": Severity}


def create_app() -> FastAPI:
    app = FastAPI(title="SOC-Swiss-Knife", version="1.0.0", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return templates.TemplateResponse("index.html", {"request": request, **_EXTRA})

    # ── IOC ──────────────────────────────────────────────────────────────────
    @app.post("/ioc", response_class=HTMLResponse)
    async def web_ioc(request: Request, indicators: str = Form(...)):
        results = []
        for line in indicators.splitlines():
            line = line.strip()
            if line:
                results.append(ioc.lookup(line))
        return templates.TemplateResponse(
            "ioc_result.html", {"request": request, "results": results, **_EXTRA}
        )

    # ── Hash ─────────────────────────────────────────────────────────────────
    @app.post("/hash", response_class=HTMLResponse)
    async def web_hash(request: Request, hashes: str = Form(...)):
        results = []
        for line in hashes.splitlines():
            line = line.strip()
            if line:
                results.append(hash_check.check(line))
        return templates.TemplateResponse(
            "hash_result.html", {"request": request, "results": results, **_EXTRA}
        )

    # ── Logs ─────────────────────────────────────────────────────────────────
    @app.post("/logs", response_class=HTMLResponse)
    async def web_logs(request: Request, log_file: UploadFile = File(...)):
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
            tmp.write(await log_file.read())
            tmp_path = tmp.name
        try:
            report = log_analyser.analyse(tmp_path)
        finally:
            os.unlink(tmp_path)
        return templates.TemplateResponse(
            "log_result.html", {"request": request, "report": report, **_EXTRA}
        )

    return app
