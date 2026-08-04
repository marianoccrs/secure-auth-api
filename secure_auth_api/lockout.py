"""Bloqueio de conta após tentativas de login com falha (defesa contra
força bruta / credential stuffing).

Regra: depois de MAX_FAILED_ATTEMPTS falhas seguidas, a conta fica
bloqueada por LOCKOUT_DURATION_SECONDS. Um login bem-sucedido zera o
contador. O bloqueio é armazenado no próprio registro do usuário
(`failed_attempts`, `locked_until`), então sobrevive a reinícios do
processo — um contador só em memória seria burlado reiniciando a API.
"""

import datetime as dt

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 15 * 60  # 15 minutos

ISO_FORMAT = "%Y-%m-%d %H:%M:%S"


def is_locked(locked_until: str | None, now: dt.datetime | None = None) -> bool:
    if not locked_until:
        return False
    now = now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    try:
        locked_until_dt = dt.datetime.strptime(locked_until, ISO_FORMAT)
    except ValueError:
        return False
    return now < locked_until_dt


def seconds_until_unlock(locked_until: str | None, now: dt.datetime | None = None) -> int:
    if not locked_until:
        return 0
    now = now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    try:
        locked_until_dt = dt.datetime.strptime(locked_until, ISO_FORMAT)
    except ValueError:
        return 0
    remaining = (locked_until_dt - now).total_seconds()
    return max(0, int(remaining))


def register_failed_attempt(failed_attempts: int, now: dt.datetime | None = None) -> tuple[int, str | None]:
    """Retorna (novo_failed_attempts, novo_locked_until).

    novo_locked_until é None a menos que esta tentativa tenha estourado o
    limite, caso em que é uma string de timestamp de quando o bloqueio acaba.
    """
    now = now or dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    new_count = failed_attempts + 1
    if new_count >= MAX_FAILED_ATTEMPTS:
        unlock_at = now + dt.timedelta(seconds=LOCKOUT_DURATION_SECONDS)
        return new_count, unlock_at.strftime(ISO_FORMAT)
    return new_count, None


def reset(now: dt.datetime | None = None) -> tuple[int, None]:
    """Estado a aplicar depois de um login bem-sucedido: zera tudo."""
    return 0, None
