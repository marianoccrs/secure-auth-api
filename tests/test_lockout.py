import datetime as dt
import unittest

from secure_auth_api import lockout


class TestLockout(unittest.TestCase):
    def test_attempts_below_threshold_do_not_lock(self):
        count = 0
        for _ in range(lockout.MAX_FAILED_ATTEMPTS - 1):
            count, locked_until = lockout.register_failed_attempt(count)
            self.assertIsNone(locked_until)
        self.assertEqual(count, lockout.MAX_FAILED_ATTEMPTS - 1)

    def test_reaching_threshold_locks_account(self):
        count = lockout.MAX_FAILED_ATTEMPTS - 1
        count, locked_until = lockout.register_failed_attempt(count)
        self.assertEqual(count, lockout.MAX_FAILED_ATTEMPTS)
        self.assertIsNotNone(locked_until)

    def test_is_locked_true_within_window(self):
        now = dt.datetime(2026, 1, 1, 12, 0, 0)
        _, locked_until = lockout.register_failed_attempt(lockout.MAX_FAILED_ATTEMPTS - 1, now=now)
        self.assertTrue(lockout.is_locked(locked_until, now=now + dt.timedelta(seconds=10)))

    def test_is_locked_false_after_window_expires(self):
        now = dt.datetime(2026, 1, 1, 12, 0, 0)
        _, locked_until = lockout.register_failed_attempt(lockout.MAX_FAILED_ATTEMPTS - 1, now=now)
        after_window = now + dt.timedelta(seconds=lockout.LOCKOUT_DURATION_SECONDS + 1)
        self.assertFalse(lockout.is_locked(locked_until, now=after_window))

    def test_seconds_until_unlock_counts_down(self):
        now = dt.datetime(2026, 1, 1, 12, 0, 0)
        _, locked_until = lockout.register_failed_attempt(lockout.MAX_FAILED_ATTEMPTS - 1, now=now)
        remaining = lockout.seconds_until_unlock(locked_until, now=now + dt.timedelta(seconds=30))
        self.assertEqual(remaining, lockout.LOCKOUT_DURATION_SECONDS - 30)

    def test_reset_clears_state(self):
        count, locked_until = lockout.reset()
        self.assertEqual(count, 0)
        self.assertIsNone(locked_until)

    def test_no_lock_state_means_not_locked(self):
        self.assertFalse(lockout.is_locked(None))
        self.assertEqual(lockout.seconds_until_unlock(None), 0)


if __name__ == "__main__":
    unittest.main()
