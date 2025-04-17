from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from fastapi import Request

def rate_limit_handler(request:Request,exc:RateLimitExceeded):
    return JSONResponse(status_code=429,
        content={
            "error": "Too Many Requests",
            "message": "You've hit the rate limit. Try again later.",
        },
        headers={"Retry-After": "60"},)