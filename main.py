from typing import Optional
import logging
from fastapi import FastAPI, File, UploadFile, HTTPException, Form

from routes.router import router
from app.orchestrator import Orchestrator

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

app = FastAPI(debug=True)
app.include_router(router,prefix="/api")

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/upload/")
async def uploader(as_file: Optional[UploadFile] = File(None), as_str:Optional[str] = Form(None)):
    if not as_file and not as_str:
        raise HTTPException(status_code=400, detail="Either .eml file or raw email string is required")
    if as_file and not as_file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are allowed")
    try:
        if as_file:
            print(f"✅ File received: {as_file.filename}")
            raw_data = await as_file.read() # read file in memory
        else:
            raw_data = as_str.encode()

        result = Orchestrator(raw_data).orchestrate()

        return {
            "filename": as_file.filename if as_file else "",
            "filesize": f"{round(len(raw_data) / 1000, 1)} KB",
            "result": result
        }

    except Exception as e:
        print(f"Error occurred: {e}\n")  # Detailed error logging
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post("/rules")
def read_item(item_id: int, q: str| None = None):
    return {"item_id": item_id, "q": q}


@app.post("/analysis")
def analysis():
    pass