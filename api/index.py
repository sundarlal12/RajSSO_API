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
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

app = FastAPI(title="RajSSO API (bootstrap)")

@app.get("/favicon.ico", include_in_schema=False)
@app.get("/favicon.png", include_in_schema=False)
def _favicon():
    return PlainTextResponse("", status_code=204)

@app.get("/_status")
def _status():
    return {"ok": True}

try:
    # your real FastAPI instance should be defined in raj_salary.py as: app = FastAPI()
    from raj_salary import app as real_app
    app.mount("/", real_app)
except Exception as e:
    @app.get("/_import_error")
    def _import_error():
        return {"error": "failed_to_import_raj_salary", "detail": str(e)}
