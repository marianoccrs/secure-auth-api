import time
import unittest

from secure_auth_api import tokens

SECRET = "test-secret-key"


class TestTokens(unittest.TestCase):
    def test_valid_token_round_trips(self):
        token = tokens.create_access_token(user_id=7, secret_key=SECRET)
        self.assertEqual(tokens.decode_access_token(token, SECRET), 7)

    def test_token_rejected_with_wrong_secret(self):
        token = tokens.create_access_token(user_id=7, secret_key=SECRET)
        with self.assertRaises(tokens.InvalidTokenError):
            tokens.decode_access_token(token, "wrong-secret")

    def test_expired_token_rejected(self):
        token = tokens.create_access_token(user_id=7, secret_key=SECRET, ttl_seconds=-1)
        with self.assertRaises(tokens.InvalidTokenError):
            tokens.decode_access_token(token, SECRET)

    def test_malformed_token_rejected(self):
        with self.assertRaises(tokens.InvalidTokenError):
            tokens.decode_access_token("not-a-jwt", SECRET)

    def test_tampered_token_rejected(self):
        token = tokens.create_access_token(user_id=7, secret_key=SECRET)
        header, payload, sig = token.split(".")
        tampered = f"{header}.{payload}.{sig[:-2]}XX"
        with self.assertRaises(tokens.InvalidTokenError):
            tokens.decode_access_token(tampered, SECRET)


if __name__ == "__main__":
    unittest.main()
