# ==== SAXO DIAGNOSTICS & REFRESH (DETAILED) ==================================
import os, time, logging, json
from fastapi import HTTPException
import httpx

log = logging.getLogger("saxo")

def _resolve_mgr():
    mgr = getattr(app.state, "saxo_mgr", None) if hasattr(app, "state") else None
    return mgr or globals().get("tm", None)

def _safe_env_info():
    return {
        "exec_enabled": os.getenv("EXEC_ENABLED"),
        "token_strategy": os.getenv("TOKEN_STRATEGY"),
        "token_storage_path": os.getenv("TOKEN_STORAGE_PATH"),
        "base_url": os.getenv("SAXO_BASE_URL"),
        "token_url": os.getenv("SAXO_TOKEN_URL") or "https://sim.logonvalidation.net/token",
        "has_app_key": bool(os.getenv("SAXO_APP_KEY")),
        "has_app_secret": bool(os.getenv("SAXO_APP_SECRET")),
        "has_refresh_token": bool(os.getenv("SAXO_REFRESH_TOKEN")),
    }

@app.post("/saxo/refresh")
async def saxo_refresh():
    mgr = _resolve_mgr()
    if not mgr:
        return {"ok": False, "reason": "TokenManager not available", "env": _safe_env_info()}
    try:
        res = await mgr.refresh_access_token()
        st  = mgr.status() if hasattr(mgr, "status") else {}
        return {"ok": True, "result": res, "status": st}
    except HTTPException as e:
        return {
            "ok": False,
            "error": "HTTPException",
            "http_status": getattr(e, "status_code", None),
            "detail": getattr(e, "detail", None),
            "env": _safe_env_info(),
        }
    except httpx.HTTPStatusError as e:
        body_preview = None
        try:
            body_preview = e.response.text[:400]
        except Exception:
            body_preview = None
        return {
            "ok": False,
            "error": "HTTPStatusError",
            "http_status": e.response.status_code,
            "reason": e.response.reason_phrase,
            "body_preview": body_preview,
            "env": _safe_env_info(),
        }
    except Exception as e:
        log.exception("Saxo refresh failed (unexpected)")
        return {
            "ok": False,
            "error": type(e).__name__,
            "detail": str(e),
            "env": _safe_env_info(),
        }

@app.post("/oauth/saxo/probe")
async def oauth_saxo_probe():
    token_url = os.getenv("SAXO_TOKEN_URL") or "https://sim.logonvalidation.net/token"
    app_key   = os.getenv("SAXO_APP_KEY")
    app_sec   = os.getenv("SAXO_APP_SECRET")
    rtok      = os.getenv("SAXO_REFRESH_TOKEN")

    missing = [k for k,v in {
        "SAXO_APP_KEY": app_key, "SAXO_APP_SECRET": app_sec, "SAXO_REFRESH_TOKEN": rtok
    }.items() if not v]
    if missing:
        return {"ok": False, "reason": "missing_env", "missing_env": missing, "env": _safe_env_info()}

    basic = f"{app_key}:{app_sec}".encode("ascii")
    auth  = "Basic " + __import__("base64").b64encode(basic).decode("ascii")
    data  = {"grant_type": "refresh_token", "refresh_token": rtok}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(token_url, headers={"Authorization": auth}, data=data)
        text = resp.text[:600] if isinstance(resp.text, str) else str(resp.text)
        try:
            j = resp.json()
        except Exception:
            j = None
        return {
            "ok": resp.status_code == 200,
            "http_status": resp.status_code,
            "json_keys": sorted(list(j.keys())) if isinstance(j, dict) else None,
            "preview": text,
            "env": _safe_env_info(),
        }
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "detail": str(e), "env": _safe_env_info()}
# =============================================================================
