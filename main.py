import logging
from logging.config import dictConfig
from fastapi import FastAPI, responses, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from routes.router import router
from app.config.limiter import limiter
from middlewares.logger import log_request
from app.config.log_conf import LOGGING_CONFIG
from handlers.rate_limit_handler import rate_limit_handler
from app.config.store import Store

dictConfig(LOGGING_CONFIG)
print("uvicorn running...")
Store.load()
app = FastAPI(debug=True)
app.state.limiter = limiter
app.include_router(router,prefix="/api")

# cors setup
origins = ["https://phishook.netlify.app/"]
app.add_middleware(middleware_class=CORSMiddleware,
                   allow_origins=origins,
                   allow_credentials=True,
                   allow_methods=["*"],
                   allow_headers=["*"])

#middlewares
app.middleware("http")(log_request)

# exception handler
app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

@app.get("/")
@limiter.limit("10/minute")
def root(request:Request):
    return responses.JSONResponse({"status":"active", "api_root":"/api/*"})


@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception):
    logging.getLogger("uvicorn.error").exception("Unhandled server error")
    return responses.JSONResponse(
        status_code=500,
        content={"error": True, "message": "Something went wrong. Please try again."},
    )
