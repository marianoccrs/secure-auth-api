"""Testes de integração da camada de orquestração (`auth.py`).

Usamos um hasher stand-in (SHA-256 puro, SEM salt/custo — nunca use isso
em produção) injetado no lugar do bcrypt real, só pra deixar esses testes
executáveis em qualquer ambiente. O que está sendo testado aqui é a
orquestração (política de senha, bloqueio, logging, emissão de token), não
a força criptográfica do hash em si — essa parte é responsabilidade do
`security.py` e é coberta separadamente em `test_security.py`
(pulada automaticamente se o bcrypt não estiver instalado).
"""

import hashlib
import unittest

from secure_auth_api import auth, lockout, security
from secure_auth_api.database import get_connection
from secure_auth_api.repository import DuplicateUserError

SECRET = "test-secret-key"
STRONG_PASSWORD = "Correct#Horse9Battery"


def _fake_hash(password: str) -> str:
    return "fake$" + hashlib.sha256(password.encode()).hexdigest()


def _fake_verify(password: str, password_hash: str) -> bool:
    return password_hash == _fake_hash(password)


class TestAuthFlow(unittest.TestCase):
    def setUp(self):
        self.conn = get_connection(":memory:")
        self.conn.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                outcome TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            """
        )

    def tearDown(self):
        self.conn.close()

    def _register(self, username="alice", password=STRONG_PASSWORD):
        return auth.register(self.conn, username, password, hash_password_fn=_fake_hash)

    def _login(self, username="alice", password=STRONG_PASSWORD):
        return auth.login(self.conn, username, password, SECRET, verify_password_fn=_fake_verify)

    def test_register_then_login_succeeds(self):
        self._register()
        token = self._login()
        user_id = auth.get_current_user_id(token, SECRET)
        self.assertIsInstance(user_id, int)

    def test_weak_password_rejected_at_register(self):
        with self.assertRaises(security.WeakPasswordError):
            self._register(password="weak")

    def test_duplicate_registration_fails(self):
        self._register()
        with self.assertRaises(DuplicateUserError):
            self._register()

    def test_wrong_password_fails_without_locking_after_one_try(self):
        self._register()
        with self.assertRaises(auth.InvalidCredentialsError):
            self._login(password="wrong-password-here")
        # Uma tentativa errada não bloqueia — só depois do limite.
        token = self._login()  # senha certa ainda funciona
        self.assertIsInstance(token, str)

    def test_account_locks_after_max_failed_attempts(self):
        self._register()
        for _ in range(lockout.MAX_FAILED_ATTEMPTS - 1):
            with self.assertRaises(auth.InvalidCredentialsError):
                self._login(password="wrong-password-here")
        # A tentativa que estoura o limite bloqueia a conta.
        with self.assertRaises(auth.InvalidCredentialsError):
            self._login(password="wrong-password-here")

        # Mesmo com a senha CERTA agora, a conta está bloqueada.
        with self.assertRaises(auth.AccountLockedError):
            self._login(password=STRONG_PASSWORD)

    def test_successful_login_resets_failed_attempt_counter(self):
        self._register()
        for _ in range(lockout.MAX_FAILED_ATTEMPTS - 2):
            with self.assertRaises(auth.InvalidCredentialsError):
                self._login(password="wrong-password-here")
        # Login certo no meio do caminho reseta o contador.
        self._login()
        # Então dá pra errar quase tudo de novo sem bloquear.
        for _ in range(lockout.MAX_FAILED_ATTEMPTS - 1):
            with self.assertRaises(auth.InvalidCredentialsError):
                self._login(password="wrong-password-here")
        token = self._login()
        self.assertIsInstance(token, str)

    def test_login_with_unknown_user_fails_without_crashing(self):
        with self.assertRaises(auth.InvalidCredentialsError):
            self._login(username="ghost")

    def test_invalid_token_raises(self):
        with self.assertRaises(auth.InvalidCredentialsError):
            auth.get_current_user_id("garbage-token", SECRET)


if __name__ == "__main__":
    unittest.main()
