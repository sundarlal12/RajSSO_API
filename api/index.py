# # api/index.py
# from fastapi import FastAPI
# from fastapi.responses import PlainTextResponse

# app = FastAPI(title="RajSSO API")

# # Avoid favicon crashes/noise in logs
# @app.get("/favicon.ico", include_in_schema=False)
# @app.get("/favicon.png", include_in_schema=False)
# def _favicon():
#     return PlainTextResponse("", status_code=204)

# @app.get("/_status")
# def _status():
#     return {"ok": True}

# # Try to load your real app
# try:
#     from raj_salary import app as real_app   # <-- your actual FastAPI instance
#     # Mount real app at root
#     app.mount("/", real_app)
# except Exception as e:
#     @app.get("/_import_error")
#     def _import_error():
#         return {"error": "failed_to_import_raj_salary", "detail": str(e)}

# api/index.py
# api/index.py
# from fastapi import FastAPI
# from fastapi.responses import PlainTextResponse, JSONResponse

# try:
#     # ✅ import your real FastAPI instance
#     from raj_salary import app as app
# except Exception as e:
#     # ⛑ if import fails, expose the error so you can see it
#     app = FastAPI(title="RajSSO API (import failed)")
#     @app.get("/_import_error")
#     def _import_error():
#         return {"error": "failed_to_import_raj_salary", "detail": str(e)}

# # quiet favicon noise
# @app.get("/favicon.ico", include_in_schema=False)
# @app.get("/favicon.png", include_in_schema=False)
# def _favicon():
#     return PlainTextResponse("", status_code=204)

# # route listing to confirm what’s actually registered
# @app.get("/_routes")
# def _routes():
#     return [{"path": r.path, "name": r.name, "methods": list(r.methods or [])} for r in app.router.routes]

# # global catcher so 500s show details (remove in prod)
# @app.exception_handler(Exception)
# async def _catch_all(request, exc):
#     return JSONResponse({"error": str(exc)}, status_code=500)
# api/index.py


# api/index.py
from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI(title="RajSSO bootstrap")

@app.get("/_status", include_in_schema=False)
def _status():
    return {"ok": True}

@app.get("/favicon.ico", include_in_schema=False)
@app.get("/favicon.png", include_in_schema=False)
def _fav():
    return PlainTextResponse("", status_code=204)

# Try importing your real app ONLY when first needed, so we can expose the error
_real_app = None
_real_app_error = None

def _load_real_app():
    global _real_app, _real_app_error
    if _real_app is not None or _real_app_error is not None:
        return
    try:
        from raj_salary import app as real_app  # import your FastAPI() instance
        _real_app = real_app
    except Exception as e:
        _real_app_error = e

@app.get("/_import_error", include_in_schema=False)
def _import_error():
    _load_real_app()
    if _real_app_error is None:
        return {"ok": True, "note": "real app imported successfully"}
    return JSONResponse({"error": "failed_to_import_raj_salary", "detail": str(_real_app_error)}, status_code=500)

# Proxy any other path to the real app (or expose the import error)
@app.api_route("/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"])
async def _proxy(path: str):
    _load_real_app()
    if _real_app_error:
        return JSONResponse({"error": "failed_to_import_raj_salary", "detail": str(_real_app_error)}, status_code=500)
    return await _real_app.router.handle({"type": "http"})  # let FastAPI handle normally
