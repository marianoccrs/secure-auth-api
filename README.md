# 🔐 Secure Auth API

> Secure REST API authentication built with Python and FastAPI.

Projeto desenvolvido para estudar **autenticação, proteção de credenciais e segurança de aplicações backend**.

---

## 🎯 Objective

Construir uma API de autenticação aplicando princípios básicos de desenvolvimento seguro.

O projeto busca compreender como mecanismos de autenticação podem ser implementados e protegidos contra ataques comuns.

---

## 🛡️ Security Features

- Password hashing com bcrypt
- JWT authentication
- Política de senhas
- Controle de tentativas de login
- Account lockout
- Input validation
- Database persistence
- Authentication controls

---

## 🔐 Authentication Flow

```text
User
 │
 ▼
Login Request
 │
 ▼
Validate Credentials
 │
 ├───────────────┐
 │               │
 ▼               ▼
Invalid         Valid
 │               │
 ▼               ▼
Track          Generate
Attempt          JWT
 │               │
 ▼               ▼
Protection    Authenticated
                Request

🧰 Technologies

    Python
    FastAPI
    SQLAlchemy
    JWT
    bcrypt
    SQL
    Git

🔎 Security Concepts

    Authentication
    Password Security
    Password Hashing
    JWT
    Brute-force Protection
    Input Validation
    Secure Credential Handling
    API Security
    Secure Coding

🚀 Running Locally

git clone <repository-url>

cd secure-auth-api

pip install -r requirements.txt

uvicorn app.main:app --reload

📚 Learning Goals

Este projeto faz parte dos meus estudos práticos em:

Backend Development + Application Security + Cybersecurity
📌 Project Status

Educational project focused on backend development and application security.
