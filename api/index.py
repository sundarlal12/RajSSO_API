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
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, JSONResponse

app = FastAPI(title="RajSSO bootstrap")

# Quiet favicon
@app.get("/favicon.ico", include_in_schema=False)
@app.get("/favicon.png", include_in_schema=False)
def _fav():
    return PlainTextResponse("", status_code=204)

@app.get("/_status")
def _status():
    return {"ok": True}

try:
    # ✅ Import your real app (the FastAPI() instance in raj_salary.py)
    from raj_salary import app as real_app
    # Mount it at root so /api/* is live
    app.mount("/", real_app)
except Exception as e:
    # ⛑ Surface import errors so you can see why /api/* isn't there
    @app.get("/_import_error")
    def _import_error():
        return {"error": "failed_to_import_raj_salary", "detail": str(e)}
