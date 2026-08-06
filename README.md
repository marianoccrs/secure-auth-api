# Secure Auth API

API REST de autenticação (FastAPI + SQLAlchemy-style SQL + bcrypt + JWT), construída pra demonstrar práticas de AppSec aplicadas desde a concepção (*secure by design*):

- **Hash de senha com bcrypt** — custo ajustável, salt embutido, resistente a ataques por força bruta offline.
- **Emissão e validação de JWT** — tokens de acesso assinados, de vida curta (15 min), via `PyJWT`.
- **Política de senha** — tamanho mínimo, exige maiúscula/minúscula/número/caractere especial, rejeita senhas comuns.
- **Bloqueio de conta após força bruta** — depois de 5 tentativas de login inválidas, a conta trava por 15 minutos. O contador zera em um login bem-sucedido.
- **Logging estruturado de tentativas de acesso** — toda tentativa de login vira uma linha de log JSON (usuário, resultado, timestamp) — a senha nunca aparece no log, nem em texto puro nem como o hash.

## Por que a estrutura é essa

A lógica de negócio de segurança (política de senha, bloqueio de conta, tokens JWT, logging) fica em módulos separados da camada HTTP, e é testada isoladamente. A única peça com dependência externa obrigatória é o hash de senha (`security.py`, via `bcrypt`) — não existe um jeito razoável de fazer hash de senha com custo ajustável usando só a biblioteca padrão, e usar algo mais fraco só pra evitar uma dependência seria pior pra segurança de verdade.

Pra manter tudo testável mesmo assim, `auth.py` (a camada que orquestra registro/login) recebe as funções de hash por injeção de dependência. Em produção o padrão é sempre `bcrypt`; nos testes de integração, um hasher baseado em `hashlib` é injetado, o que permite testar toda a lógica de bloqueio/logging/token sem precisar do bcrypt instalado.

```
secure_auth_api/
├── database.py         # sqlite3 + schema (SQL parametrizado)
├── security.py          # hash de senha (bcrypt) + política de senha
├── tokens.py             # emissão/validação de JWT (PyJWT)
├── lockout.py             # regra de bloqueio de conta após N falhas
├── logging_config.py       # log estruturado (JSON) de tentativas de acesso
├── repository.py            # acesso a dados
├── auth.py                   # orquestra tudo acima (register/login)
├── schemas.py                 # validação de entrada (Pydantic)
└── main.py                     # rotas FastAPI (camada HTTP fina)
```

## Configuração

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export SECURE_AUTH_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
uvicorn secure_auth_api.main:app --reload
```

API em `http://127.0.0.1:8000`, docs interativas em `http://127.0.0.1:8000/docs`.

## Rodando os testes

```bash
python -m unittest discover -s tests -v
```

36 testes no total — 33 rodam sem nenhuma dependência externa (política de senha, bloqueio de conta, JWT, acesso a dados, orquestração completa de registro/login com um hasher injetado). Os 3 testes que usam `bcrypt` de verdade (`test_security.py::TestBcryptHashing`) são pulados automaticamente se o pacote não estiver instalado, e rodam normalmente depois do `pip install -r requirements.txt`.

## Demonstração manual de ponta a ponta

Com o servidor rodando:

```bash
python demo.py
```

Mostra uma senha fraca sendo rejeitada no registro, e uma conta sendo bloqueada (`423 Locked`) depois de 5 tentativas de login com senha errada — inclusive continuando bloqueada mesmo quando a senha certa é usada em seguida.

## API

| Método | Rota        | Auth | Descrição                                      |
|--------|-------------|------|--------------------------------------------------|
| POST   | `/register` | —    | Cria um usuário (aplica a política de senha)     |
| POST   | `/login`    | —    | Retorna um JWT (aplica o bloqueio de força bruta)|
| GET    | `/me`       | ✔    | Retorna os dados do usuário autenticado          |

Rotas autenticadas esperam `Authorization: Bearer <token>`.

## Observações / o que eu mudaria em produção

- Access token de 15 minutos sem refresh token — em produção eu adicionaria um refresh token de vida mais longa, armazenado com rotação, pra não forçar login toda hora.
- O bloqueio de conta é por username; em produção também vale considerar limitar por IP, pra dificultar um ataque distribuído entre várias contas.
- O log estruturado aqui vai pro stdout; em produção eu mandaria pra um serviço centralizado (ex: CloudWatch, Datadog) com alerta automático em picos de `login_failed`/`account_locked`.

## Licença

MIT — veja [LICENSE](LICENSE).
