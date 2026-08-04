"""Emissão e validação de JWT, usando a lib PyJWT (padrão de mercado).

Tokens de acesso carregam `sub` (id do usuário), `iat` e `exp`. O segredo
de assinatura vem de fora (variável de ambiente) — nunca fica hardcoded.
"""

import time

import jwt

ALGORITHM = "HS256"
ACCESS_TOKEN_TTL_SECONDS = 15 * 60  # 15 minutos — token de acesso de vida curta


class InvalidTokenError(Exception):
    pass


def create_access_token(user_id: int, secret_key: str, ttl_seconds: int = ACCESS_TOKEN_TTL_SECONDS) -> str:
    now = int(time.time())
    payload = {"sub": str(user_id), "iat": now, "exp": now + ttl_seconds}
    return jwt.encode(payload, secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str, secret_key: str) -> int:
    """Retorna o user_id se o token for válido; levanta InvalidTokenError caso contrário."""
    try:
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise InvalidTokenError("token expirado")
    except jwt.InvalidTokenError:
        raise InvalidTokenError("token inválido")

    try:
        return int(payload["sub"])
    except (KeyError, ValueError):
        raise InvalidTokenError("token sem 'sub' válido")
