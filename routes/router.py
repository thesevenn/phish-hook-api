import logging
from typing import Optional
from fastapi import routing, File, UploadFile, HTTPException, Form, responses,Request

from app.orchestrator import Orchestrator
from app.config.limiter import limiter

router = routing.APIRouter()
logger = logging.getLogger("uvicorn.error")


@router.post("/analyze")
@limiter.limit("5/minute")
async def uploader(request:Request,as_file: Optional[UploadFile] = File(None), as_str:Optional[str] = Form(None)):
    if not as_file and not as_str:
        raise HTTPException(status_code=400, detail="Either .eml file or raw email string is required")
    if as_file and not as_file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Invalid file type found, only (.eml) file accepted")

    try:
        if as_file:
            print(f"✅ File received: {as_file.filename}")
            raw_data = await as_file.read() # read file in memory
        else:
            raw_data = as_str.encode()
        result = Orchestrator(raw_data).orchestrate()

        return responses.JSONResponse({
            "filename": as_file.filename if as_file else "",
            "email_size": f"{round(len(raw_data) / 1000, 1)} KB",
            "result": result
        })

    except Exception as e:
        print(f"Error occurred: {e}\n")  # Detailed error logging
        logger.error("Error:{e}",exc_info=True)
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.get("/status")
@limiter.limit("10/minute")
def status(request:Request):
    try:
        return responses.JSONResponse({"status":"active", "health":"ok"})
    except Exception as e:
        return responses.JSONResponse(status_code=500,content={"status":"inactive","health":"error"})
