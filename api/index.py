# from raj_salary import app
# from fastapi import FastAPI
# from fastapi.responses import JSONResponse

# # Vercel uses a function handler
# def handler(event, context):
#     from mangum import Mangum
#     asgi_handler = Mangum(app)
#     return asgi_handler(event, context)

# api/index.py
from raj_salary import app  # FastAPI() instance
