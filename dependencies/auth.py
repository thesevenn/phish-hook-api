import os

from fastapi import Header, HTTPException

API_KEY = os.environ.get("ADM_API_KEY")
def is_valid_auth(x_api_key:str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API KEY")
