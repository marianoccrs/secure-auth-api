"""Orquestração de registro/login: junta política de senha, hashing,
bloqueio de conta, emissão de token e logging de acesso.

As funções de hash/verificação de senha são recebidas por parâmetro (com
`security.hash_password`/`security.verify_password` como padrão), então
esta camada — que é onde a lógica de negócio de segurança realmente mora
(quando bloquear, o que logar, quando emitir token) — é testável mesmo em
ambientes sem `bcrypt` instalado, injetando um hasher stand-in nos testes.
"""

import datetime as dt
import sqlite3
from typing import Callable

from . import lockout, security, tokens
from .logging_config import log_access_attempt
from .repository import AccessLogRepository, UserRepository

HashFn = Callable[[str], str]
VerifyFn = Callable[[str, str], bool]


class InvalidCredentialsError(Exception):
    pass


class AccountLockedError(Exception):
    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"account locked, retry in {retry_after_seconds}s")


def register(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    hash_password_fn: HashFn = security.hash_password,
):
    username = username.strip()
    if not username:
        raise ValueError("username must not be empty")

    security.validate_password_policy(password)  # levanta WeakPasswordError se fraca

    password_hash = hash_password_fn(password)
    users = UserRepository(conn)
    user = users.create(username, password_hash)
    log_access_attempt(username, "register_success")
    return user


def login(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    secret_key: str,
    verify_password_fn: VerifyFn = security.verify_password,
    now: dt.datetime | None = None,
) -> str:
    """Retorna um access token JWT se as credenciais forem válidas.

    Levanta AccountLockedError se a conta estiver temporariamente
    bloqueada, ou InvalidCredentialsError pra usuário desconhecido ou
    senha errada (a mesma exceção pros dois casos — não revelamos qual
    dos dois foi)."""
    username = username.strip()
    now = now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    users = UserRepository(conn)
    access_log = AccessLogRepository(conn)

    user = users.get_by_username(username)

    if user is not None and lockout.is_locked(user.locked_until, now):
        retry_after = lockout.seconds_until_unlock(user.locked_until, now)
        log_access_attempt(username, "blocked_locked_account")
        raise AccountLockedError(retry_after)

    if user is None or not verify_password_fn(password, user.password_hash):
        if user is not None:
            new_count, new_locked_until = lockout.register_failed_attempt(user.failed_attempts, now)
            users.set_lockout_state(user.id, new_count, new_locked_until)
            outcome = "account_locked" if new_locked_until else "login_failed"
        else:
            outcome = "login_failed_unknown_user"
        access_log.record(username, outcome)
        log_access_attempt(username, outcome)
        raise InvalidCredentialsError("invalid username or password")

    # Sucesso: zera o contador de tentativas e emite o token.
    reset_count, reset_locked = lockout.reset()
    users.set_lockout_state(user.id, reset_count, reset_locked)
    access_log.record(username, "login_success")
    log_access_attempt(username, "login_success")
    return tokens.create_access_token(user.id, secret_key)


def get_current_user_id(token: str, secret_key: str) -> int:
    try:
        return tokens.decode_access_token(token, secret_key)
    except tokens.InvalidTokenError:
        raise InvalidCredentialsError("invalid or expired token")
