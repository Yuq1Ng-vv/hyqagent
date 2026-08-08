"""FastAPI test fixture for framework extractor tests."""

from typing import Optional

from fastapi import Cookie, Depends, FastAPI, Header, Path, Query

app = FastAPI()


def get_current_user():
    return {"username": "admin"}


@app.get("/")
def index():
    return {"status": "ok"}


@app.get("/users")
def list_users(page: int = Query(1), q: Optional[str] = Query(None)):
    return {"page": page, "q": q}


@app.get("/users/{user_id}")
def get_user(user_id: int = Path(...), token: str = Header(None)):
    return {"id": user_id}


@app.post("/users")
def create_user(name: str = Body(...), email: str = Body(...)):
    return {"status": "created", "name": name, "email": email}


@app.put("/users/{user_id}")
def update_user(user_id: int, payload: dict = Body(...)):
    return {"id": user_id}


@app.delete("/users/{user_id}")
def delete_user(user_id: int, current_user=Depends(get_current_user)):
    return {"deleted": user_id}


@app.patch("/items/{item_id}")
def patch_item(item_id: str = Path(...)):
    return {"item_id": item_id}


@app.get("/search")
def search_items(
    q: str = Query(...),
    session_id: Optional[str] = Cookie(None),
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    return {"q": q}


@app.get("/admin/dashboard")
def admin_dashboard(
    current_user=Depends(get_current_user),
    authorization: str = Header(...),
):
    user_agent = request.headers.get("User-Agent")
    session = Cookie("session_id")
    return {"user": current_user, "ua": user_agent}
