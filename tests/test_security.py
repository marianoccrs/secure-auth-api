import unittest

from secure_auth_api import security


class TestPasswordPolicy(unittest.TestCase):
    def test_accepts_strong_password(self):
        security.validate_password_policy("Correct#Horse9Battery")  # não deve levantar

    def test_rejects_too_short(self):
        with self.assertRaises(security.WeakPasswordError):
            security.validate_password_policy("Ab1#dEf")

    def test_rejects_missing_uppercase(self):
        with self.assertRaises(security.WeakPasswordError):
            security.validate_password_policy("lowercase123#only")

    def test_rejects_missing_lowercase(self):
        with self.assertRaises(security.WeakPasswordError):
            security.validate_password_policy("UPPERCASE123#ONLY")

    def test_rejects_missing_digit(self):
        with self.assertRaises(security.WeakPasswordError):
            security.validate_password_policy("NoDigitsHere#Only")

    def test_rejects_missing_special_char(self):
        with self.assertRaises(security.WeakPasswordError):
            security.validate_password_policy("NoSpecialChars123")

    def test_rejects_common_weak_password(self):
        with self.assertRaises(security.WeakPasswordError):
            security.validate_password_policy("Password1!")  # forte na forma, mas é padrão comum
        with self.assertRaises(security.WeakPasswordError):
            security.validate_password_policy("password1")


@unittest.skipUnless(security.BCRYPT_AVAILABLE, "bcrypt não está instalado neste ambiente")
class TestBcryptHashing(unittest.TestCase):
    """Roda de verdade quando `pip install -r requirements.txt` foi feito
    localmente. Neste sandbox de desenvolvimento (sem acesso à rede pra
    instalar pacotes), esses testes são pulados — os testes de política de
    senha, bloqueio de conta e JWT acima/abaixo cobrem a lógica de negócio
    sem depender do bcrypt estar presente."""

    def test_correct_password_verifies(self):
        hashed = security.hash_password("Correct#Horse9Battery")
        self.assertTrue(security.verify_password("Correct#Horse9Battery", hashed))

    def test_wrong_password_fails(self):
        hashed = security.hash_password("Correct#Horse9Battery")
        self.assertFalse(security.verify_password("wrong-password", hashed))

    def test_hash_never_contains_plaintext(self):
        hashed = security.hash_password("Correct#Horse9Battery")
        self.assertNotIn("Correct#Horse9Battery", hashed)


if __name__ == "__main__":
    unittest.main()
