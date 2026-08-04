"""Secure Auth API — API de autenticação (FastAPI + SQLAlchemy) com:

  * Hash de senha com bcrypt
  * Emissão e validação de JWT
  * Política de senha (tamanho mínimo, complexidade, lista de senhas fracas comuns)
  * Bloqueio de conta após N tentativas de login inválidas (defesa contra força bruta)
  * Log estruturado de tentativas de acesso (sem nunca logar a senha)

Assim como nos outros projetos da série, a lógica crítica de segurança
(política de senha, bloqueio de conta, tokens, acesso a dados) fica em
módulos que dependem só da biblioteca padrão + PyJWT, e são testados
isoladamente. `security.py` usa bcrypt de verdade pra produção, mas a
camada de orquestração (`auth.py`) recebe o hasher por injeção de
dependência, então os testes de lockout/JWT/logging rodam mesmo sem
bcrypt instalado no ambiente.
"""
