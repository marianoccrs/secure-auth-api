"""Demo de ponta a ponta contra um servidor rodando de verdade.

Uso:
    # terminal 1
    export SECURE_AUTH_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
    uvicorn secure_auth_api.main:app --reload

    # terminal 2
    python demo.py
"""

import json
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8000"
STRONG_PASSWORD = "Correct#Horse9Battery"


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(BASE_URL + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"null")


def main():
    print("1. Tentando registrar com senha fraca (deve ser rejeitado)...")
    status, body = call("POST", "/register", {"username": "demo_user", "password": "fraca"})
    print(f"   -> HTTP {status}: {body}\n")
    assert status == 422

    print("2. Registrando com senha forte...")
    status, body = call("POST", "/register", {"username": "demo_user", "password": STRONG_PASSWORD})
    print(f"   -> HTTP {status}: {body}\n")

    print("3. Login com senha errada 5 vezes seguidas (deve bloquear a conta)...")
    for i in range(5):
        status, body = call("POST", "/login", {"username": "demo_user", "password": "senha-errada"})
        print(f"   tentativa {i + 1} -> HTTP {status}: {body}")

    print("\n4. Tentando logar com a senha CERTA agora (deve continuar bloqueado)...")
    status, body = call("POST", "/login", {"username": "demo_user", "password": STRONG_PASSWORD})
    print(f"   -> HTTP {status}: {body}")
    assert status == 423, "bloqueio de conta falhou!"
    print("   Bloqueado como esperado (423 Locked).\n")

    print("Todas as checagens passaram.")


if __name__ == "__main__":
    main()
