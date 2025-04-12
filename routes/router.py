from fastapi import routing

router = routing.APIRouter()

@router.get("/user")
def user():
    return "hello"