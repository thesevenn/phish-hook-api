import time
import logging
from fastapi import Request

logger = logging.getLogger("requests")

async def log_request(request:Request,call_next):
    start_time = time.time()

    method = request.method
    path = request.url.path
    client_ip = request.client.host if request.client else "unknown"

    logger.info(f"{method} {path}")

    try:
        response = await call_next(request)
    except Exception:
        error_logger = logging.getLogger("uvicorn.error")
        error_logger.exception("Unhandled Exception")
        raise

    process_time = (time.time() - start_time) * 1000
    status = response.status_code

    logger.info(f"{method} {path} | {status} | {process_time:.2f}ms | {client_ip}")
    return response

