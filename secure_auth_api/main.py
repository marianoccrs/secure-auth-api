"""Aplicação FastAPI — camada HTTP fina em cima de `auth.py`.

Rotas só validam entrada (Pydantic) e traduzem exceções de domínio pra
status HTTP. Toda a lógica de segurança (política de senha, bloqueio,
JWT, logging) já foi testada isoladamente em `tests/`.
"""

import os
import sqlite3

from fastapi import Depends, FastAPI, Header, HTTPException, status

from . import auth, security
from .database import get_connection, init_db
from .repository import DuplicateUserError
from .schemas import Token, UserCreate, UserLogin, UserOut

DB_PATH = os.environ.get("SECURE_AUTH_DB", "app.db")
SECRET_KEY = os.environ.get("SECURE_AUTH_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "a variável de ambiente SECURE_AUTH_SECRET_KEY precisa estar definida "
        "(ex: gere uma com: python -c \"import secrets; print(secrets.token_hex(32))\")"
    )

app = FastAPI(title="Secure Auth API", version="1.0.0")


@app.on_event("startup")
def on_startup():
    init_db(DB_PATH)


def get_db():
    conn = get_connection(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


def get_current_user_id(authorization: str = Header(default="")) -> int:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        return auth.get_current_user_id(token, SECRET_KEY)
    except auth.InvalidCredentialsError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired token")


@app.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserCreate, conn: sqlite3.Connection = Depends(get_db)):
    try:
        user = auth.register(conn, payload.username, payload.password)
    except DuplicateUserError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username already taken")
    except security.WeakPasswordError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    return UserOut(id=user.id, username=user.username)


@app.post("/login", response_model=Token)
def login_user(payload: UserLogin, conn: sqlite3.Connection = Depends(get_db)):
    try:
        token = auth.login(conn, payload.username, payload.password, SECRET_KEY)
    except auth.AccountLockedError as exc:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"account temporarily locked, try again in {exc.retry_after_seconds}s",
        )
    except auth.InvalidCredentialsError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid username or password")
    return Token(access_token=token)


@app.get("/me", response_model=UserOut)
def read_current_user(
    user_id: int = Depends(get_current_user_id),
    conn: sqlite3.Connection = Depends(get_db),
):
    from .repository import UserRepository

    user = UserRepository(conn).get_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    return UserOut(id=user.id, username=user.username)
