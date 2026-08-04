"""Camada de acesso a dados — sempre com queries parametrizadas."""

import sqlite3
from dataclasses import dataclass


class DuplicateUserError(Exception):
    pass


@dataclass
class User:
    id: int
    username: str
    password_hash: str
    failed_attempts: int
    locked_until: str | None


class UserRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def create(self, username: str, password_hash: str) -> User:
        try:
            cur = self.conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
        except sqlite3.IntegrityError as exc:
            raise DuplicateUserError(f"username '{username}' already exists") from exc
        self.conn.commit()
        return User(id=cur.lastrowid, username=username, password_hash=password_hash,
                    failed_attempts=0, locked_until=None)

    def get_by_username(self, username: str) -> User | None:
        row = self.conn.execute(
            "SELECT id, username, password_hash, failed_attempts, locked_until "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return User(**dict(row)) if row else None

    def get_by_id(self, user_id: int) -> User | None:
        row = self.conn.execute(
            "SELECT id, username, password_hash, failed_attempts, locked_until "
            "FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return User(**dict(row)) if row else None

    def set_lockout_state(self, user_id: int, failed_attempts: int, locked_until: str | None) -> None:
        self.conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (failed_attempts, locked_until, user_id),
        )
        self.conn.commit()


class AccessLogRepository:
    """Registro append-only de tentativas de acesso. Nunca recebe a senha."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def record(self, username: str, outcome: str, detail: str | None = None) -> None:
        self.conn.execute(
            "INSERT INTO access_log (username, outcome, detail) VALUES (?, ?, ?)",
            (username, outcome, detail),
        )
        self.conn.commit()

    def recent_for_user(self, username: str, limit: int = 20) -> list[dict]:
        rows = self.conn.execute(
            "SELECT username, outcome, detail, created_at FROM access_log "
            "WHERE username = ? ORDER BY id DESC LIMIT ?",
            (username, limit),
        ).fetchall()
        return [dict(r) for r in rows]
