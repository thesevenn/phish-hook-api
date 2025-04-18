import os

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s %(asctime)s | %(name)s | %(message)s",
            "use_colors": None,
        },
        "detailed": {
            "format": "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
        "file_requests": {
            "class": "logging.FileHandler",
            "formatter": "detailed",
            "filename": f"{LOG_DIR}/requests.log",
            "mode": "a",
        },
        "file_errors": {
            "class": "logging.FileHandler",
            "formatter": "detailed",
            "filename": f"{LOG_DIR}/errors.log",
            "mode": "a",
        },
        "file_detections": {
            "class": "logging.FileHandler",
            "formatter": "detailed",
            "filename": f"{LOG_DIR}/detections.log",
            "mode": "a",
        },
    },
    "loggers": {
        "uvicorn": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "uvicorn.error": {
            "level": "ERROR",
            "handlers": ["console", "file_errors"],
            "propagate": False,
        },
        "uvicorn.access": {
            "level": "INFO",
            "handlers": ["console", "file_requests"],
            "propagate": False,
        },
        "detection": {
            "level": "INFO",
            "handlers": ["console", "file_detections"],
            "propagate": False,
        },
        "requests": {
            "level": "INFO",
            "handlers": ["console", "file_requests"],
            "propagate": False,
        },
    },
}
