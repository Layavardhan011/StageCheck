"""Unit Tests for Dynamic Git Remote Authority Whitelist (FP-STAGECHECK-REMOTE-ORG / SR-08 / DEC-021)."""

import unittest
from checks.authority import approved_remote


class TestAuthorityRemote(unittest.TestCase):
    """Test dynamic remote matching without hardcoded organization paths."""

    def test_dynamic_remote_parsing(self):
        """Verify dynamic remote authority parsing and elimination of hardcoded xorewa/."""
        approved = {
            "git@github.com:acme-corp/payment-service.git",
            "https://github.com/acme-corp/ledger-api.git",
            "ssh://git@gitlab.com/internal/auth-service.git",
        }

        # 1. DISABLED is always accepted
        self.assertTrue(approved_remote("DISABLED", approved))

        # 2. Approved SSH remote passes (non-xorewa organization)
        self.assertTrue(
            approved_remote("git@github.com:acme-corp/payment-service.git", approved)
        )

        # 3. Approved HTTPS remote passes
        self.assertTrue(
            approved_remote("https://github.com/acme-corp/ledger-api.git", approved)
        )

        # 4. Approved ssh:// remote passes
        self.assertTrue(
            approved_remote("ssh://git@gitlab.com/internal/auth-service.git", approved)
        )

        # 5. Unapproved remote fails
        self.assertFalse(
            approved_remote("git@github.com:attacker/malicious.git", approved)
        )

        # 6. Blacklisted legacy endpoint fails even if somehow in approved list
        blacklisted = {
            "https://multiversx.com/repo.git",
            "git@elrond.com:repo.git",
            "https://api.multiversx.com/git/repo",
        }
        for bad_url in blacklisted:
            self.assertFalse(
                approved_remote(bad_url, approved | blacklisted),
                f"Expected blacklisted endpoint '{bad_url}' to be rejected",
            )


if __name__ == "__main__":
    unittest.main()

