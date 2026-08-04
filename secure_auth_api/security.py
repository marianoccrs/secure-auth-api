"""Hash de senha (bcrypt) e política de senha.

O hashing de senha usa `bcrypt` de verdade — é o padrão da indústria pra
essa finalidade (custo ajustável, salt embutido, resistente a GPU/ASIC).
Essa é a única peça do projeto com uma dependência externa obrigatória:
não existe um substituto de biblioteca padrão razoável pra hash de senha
com custo ajustável, e usar algo mais fraco só pra "não depender de nada"
seria pior pra segurança de verdade — então aqui a dependência vale a pena.

`auth.py` recebe as funções de hash por injeção de dependência, então a
lógica de orquestração (bloqueio de conta, emissão de token, logging)
continua testável mesmo em ambientes sem bcrypt instalado.
"""

import re

try:
    import bcrypt

    BCRYPT_AVAILABLE = True
except ImportError:  # pragma: no cover
    BCRYPT_AVAILABLE = False

BCRYPT_ROUNDS = 12

MIN_LENGTH = 10

# Lista pequena e ilustrativa de senhas comuns rejeitadas pela política —
# não é (nem tenta ser) uma wordlist de cracking, só bloqueia os casos mais
# óbvios que checagens de comprimento/complexidade sozinhas deixam passar.
COMMON_WEAK_PASSWORDS = {
    "password", "password1", "12345678", "123456789", "qwerty123",
    "letmein1", "senha123", "admin123", "iloveyou1", "welcome1",
    "password1!", "welcome1!", "admin123!",
}


class WeakPasswordError(ValueError):
    """Levantada quando uma senha não atende à política."""


def validate_password_policy(password: str) -> None:
    """Levanta WeakPasswordError com uma mensagem explicando o motivo,
    ou não faz nada se a senha for aceitável."""
    if len(password) < MIN_LENGTH:
        raise WeakPasswordError(f"a senha precisa ter pelo menos {MIN_LENGTH} caracteres")
    if not re.search(r"[a-z]", password):
        raise WeakPasswordError("a senha precisa ter pelo menos uma letra minúscula")
    if not re.search(r"[A-Z]", password):
        raise WeakPasswordError("a senha precisa ter pelo menos uma letra maiúscula")
    if not re.search(r"\d", password):
        raise WeakPasswordError("a senha precisa ter pelo menos um número")
    if not re.search(r"[^\w\s]", password):
        raise WeakPasswordError("a senha precisa ter pelo menos um caractere especial")
    if password.lower() in COMMON_WEAK_PASSWORDS:
        raise WeakPasswordError("essa senha é comum demais — escolha outra")


def hash_password(password: str) -> str:
    if not BCRYPT_AVAILABLE:
        raise RuntimeError(
            "o pacote 'bcrypt' não está instalado — rode `pip install -r requirements.txt`"
        )
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not BCRYPT_AVAILABLE:
        raise RuntimeError(
            "o pacote 'bcrypt' não está instalado — rode `pip install -r requirements.txt`"
        )
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
