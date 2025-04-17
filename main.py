import logging
from logging.config import dictConfig
from fastapi import FastAPI, responses

from routes.router import router
from app.config.logging import LOGGING_CONFIG
from middlewares.logger import log_request

dictConfig(LOGGING_CONFIG)

app = FastAPI(debug=True)
app.include_router(router,prefix="/api")

#middlewares
app.middleware("http")(log_request)

@app.get("/")
def root():
    return responses.JSONResponse({"status":"active", "api_path":"/api[/path]"})


@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception):
    logging.getLogger("uvicorn.error").exception("Unhandled server error")
    return responses.JSONResponse(
        status_code=500,
        content={"error": True, "message": "Something went wrong. Please try again."},
    )
