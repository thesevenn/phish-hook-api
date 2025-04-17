from typing import Optional
from fastapi import routing, File, UploadFile, HTTPException, Form, responses

from app.orchestrator import Orchestrator

router = routing.APIRouter()

@router.post("/analyze")
async def uploader(as_file: Optional[UploadFile] = File(None), as_str:Optional[str] = Form(None)):
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
            "filesize": f"{round(len(raw_data) / 1000, 1)} KB",
            "result": result
        })

    except Exception as e:
        print(f"Error occurred: {e}\n")  # Detailed error logging
        raise HTTPException(status_code=500, detail="Internal Server Error")

@router.get("/status")
def status():
    try:
        return responses.JSONResponse({"status":"active", "health":"ok"})
    except Exception as e:
        return responses.JSONResponse({"status":"inactive","health":"error"})
