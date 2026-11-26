"""FastAPI app: CONTRACT routes + login + static UI.  Run:  uvicorn vai.web.app:app"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .service import Service, ServiceError, Settings

STATIC = Path(__file__).parent / "static"
TTL = 8 * 3600


def create_app(settings: Settings | None = None) -> FastAPI:
    st = settings or Settings()
    svc = Service(st)
    app = FastAPI(title="Verifiable AI Investigator - web", docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.service = svc
    secret = os.urandom(32)
    fails: dict[str, list[float]] = {}
    if not st.demo_password:
        print("WARNING: DEMO_PASSWORD is not set - login is OFF (fine for a local offline demo only).")

    def sign(msg: str) -> str:
        return hmac.new(secret, msg.encode(), hashlib.sha256).hexdigest()

    def auth(request: Request):
        if not st.demo_password:
            return
        tok = request.cookies.get("vai_session", "")
        try:
            exp, sig = tok.split(".")
            if hmac.compare_digest(sig, sign(exp)) and int(exp) > time.time():
                return
        except Exception:
            pass
        raise HTTPException(401, "Login required")

    @app.exception_handler(ServiceError)
    async def _svc_err(_, e: ServiceError):
        return JSONResponse({"detail": e.message}, status_code=e.status)

    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.update({
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; "
                                       "img-src 'self' data:; frame-ancestors 'none'"})
        if request.url.path.startswith("/api"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---- login
    @app.get("/api/health")
    def health():
        return {"ok": True}

    @app.get("/api/me")
    def me(request: Request):
        try:
            auth(request)
            return {"authenticated": True, "login_required": bool(st.demo_password)}
        except HTTPException:
            return {"authenticated": False, "login_required": True}

    @app.post("/api/login")
    def login(request: Request, response: Response, body: dict = Body(...)):
        ip = request.client.host if request.client else "?"
        now = time.time()
        recent = [t for t in fails.get(ip, []) if now - t < 60]
        if len(recent) >= 5:
            raise HTTPException(429, "Too many attempts. Wait a minute.")
        if st.demo_password and not hmac.compare_digest(str(body.get("password", "")), st.demo_password):
            fails[ip] = recent + [now]
            raise HTTPException(401, "Wrong password")
        exp = str(int(now) + TTL)
        response.set_cookie("vai_session", f"{exp}.{sign(exp)}", httponly=True, samesite="strict", max_age=TTL,
                            secure=request.url.scheme == "https")
        return {"authenticated": True}

    @app.post("/api/logout")
    def logout(response: Response):
        response.delete_cookie("vai_session")
        return {"authenticated": False}

    # ---- CONTRACT routes
    @app.get("/api/cases", dependencies=[Depends(auth)])
    def cases():
        return svc.list_cases()

    @app.get("/api/cases/{cid}", dependencies=[Depends(auth)])
    def case(cid: str, events: str = Query("all", pattern="^(all|linked|none)$")):
        return svc.get_case(cid, events)

    @app.post("/api/cases/{cid}/run", dependencies=[Depends(auth)])
    def run(cid: str, wait: bool = False, fresh: bool = False):
        svc.run(cid, wait=wait, fresh=fresh)
        return {"case_id": cid, "status": "done" if wait else "started"}

    @app.post("/api/cases/{cid}/verify", dependencies=[Depends(auth)])
    def verify(cid: str):
        return svc.verify(cid)

    @app.post("/api/cases/{cid}/tamper-demo", dependencies=[Depends(auth)])
    def tamper(cid: str, body: dict = Body(default={})):
        return svc.tamper(cid, body.get("mode", "edit"), body.get("step"), body.get("seq"))

    @app.get("/api/cases/{cid}/why", dependencies=[Depends(auth)])
    def why(cid: str):
        return svc.why(cid)

    @app.post("/api/cases/{cid}/approve", dependencies=[Depends(auth)])
    def approve(cid: str, body: dict = Body(default={})):
        return svc.approve(cid, body.get("officer"))

    def pdf(data: bytes, name: str, inline=True):
        return Response(data, media_type="application/pdf", headers={
            "Content-Disposition": f'{"inline" if inline else "attachment"}; filename="{name}"'})

    @app.get("/api/cases/{cid}/report", dependencies=[Depends(auth)])
    def report(cid: str):
        return pdf(svc.report(cid), f"{cid}_report.pdf")

    @app.get("/api/cases/{cid}/s63", dependencies=[Depends(auth)])
    def s63(cid: str):
        return pdf(svc.s63(cid), f"{cid}_s63_DRAFT.pdf")

    # ---- extra routes (additive)
    @app.post("/api/cases/{cid}/completeness", dependencies=[Depends(auth)])
    def completeness(cid: str):
        return svc.completeness(cid)

    @app.post("/api/cases/{cid}/restore-demo", dependencies=[Depends(auth)])
    def restore(cid: str):
        return svc.restore(cid)

    @app.get("/api/cases/{cid}/ledger", dependencies=[Depends(auth)])
    def ledger(cid: str):
        return svc.ledger_view(cid)

    @app.get("/api/cases/{cid}/proof/{seq}", dependencies=[Depends(auth)])
    def proof(cid: str, seq: int):
        return svc.proof(cid, seq)

    @app.get("/api/cases/{cid}/export", dependencies=[Depends(auth)])
    def export(cid: str):
        return Response(svc.export(cid), media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{cid}_evidence_package.zip"'})

    @app.post("/api/cases/{cid}/evidence", dependencies=[Depends(auth)])
    async def upload(cid: str, request: Request):
        name = request.headers.get("x-filename", "upload.bin")
        return svc.upload(cid, name, await request.body())

    # ---- UI
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})

    return app


app = create_app() if os.getenv("VAI_NO_AUTOAPP") != "1" else None
