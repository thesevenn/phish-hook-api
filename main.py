import logging
from logging.config import dictConfig
from fastapi import FastAPI, responses, Request
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from routes.router import router
from app.config.limiter import limiter
from middlewares.logger import log_request
from app.config.logging import LOGGING_CONFIG

dictConfig(LOGGING_CONFIG)

app = FastAPI(debug=True)
app.include_router(router,prefix="/api")
app.state.limiter = limiter

#middlewares
app.middleware("http")(log_request)


@app.get("/")
@limiter.limit("10/minute")
def root(request:Request):
    return responses.JSONResponse({"status":"active", "api_path":"/api[/path]"})


app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception):
    logging.getLogger("uvicorn.error").exception("Unhandled server error")
    return responses.JSONResponse(
        status_code=500,
        content={"error": True, "message": "Something went wrong. Please try again."},
    )
