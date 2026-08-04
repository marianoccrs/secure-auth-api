import unittest

from secure_auth_api.database import get_connection
from secure_auth_api.repository import AccessLogRepository, DuplicateUserError, UserRepository


class RepositoryTestCase(unittest.TestCase):
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
        self.users = UserRepository(self.conn)
        self.access_log = AccessLogRepository(self.conn)

    def tearDown(self):
        self.conn.close()


class TestUserRepository(RepositoryTestCase):
    def test_create_and_fetch(self):
        created = self.users.create("alice", "hashed")
        fetched = self.users.get_by_username("alice")
        self.assertEqual(created.id, fetched.id)
        self.assertEqual(fetched.failed_attempts, 0)
        self.assertIsNone(fetched.locked_until)

    def test_duplicate_username_rejected(self):
        self.users.create("alice", "hashed")
        with self.assertRaises(DuplicateUserError):
            self.users.create("alice", "other-hash")

    def test_sql_injection_payload_stored_literally(self):
        payload = "alice'; DROP TABLE users; --"
        self.users.create(payload, "hashed")
        fetched = self.users.get_by_username(payload)
        self.assertIsNotNone(fetched)
        # A tabela continua íntegra e consultável normalmente.
        self.assertIsNone(self.users.get_by_username("alice"))

    def test_set_lockout_state_persists(self):
        user = self.users.create("bob", "hashed")
        self.users.set_lockout_state(user.id, 3, "2026-01-01 00:00:00")
        fetched = self.users.get_by_id(user.id)
        self.assertEqual(fetched.failed_attempts, 3)
        self.assertEqual(fetched.locked_until, "2026-01-01 00:00:00")


class TestAccessLogRepository(RepositoryTestCase):
    def test_record_and_read_back(self):
        self.access_log.record("alice", "login_failed", "bad password")
        entries = self.access_log.recent_for_user("alice")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["outcome"], "login_failed")

    def test_log_never_needs_a_password_field(self):
        # A assinatura de record() nem aceita senha — não tem como um
        # chamador acidentalmente logar uma. Isso é o teste de "a API do
        # próprio código impede o vazamento", não uma checagem de valor.
        import inspect

        params = inspect.signature(self.access_log.record).parameters
        self.assertNotIn("password", params)


if __name__ == "__main__":
    unittest.main()
