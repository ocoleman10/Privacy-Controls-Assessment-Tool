"""Synthetic fixture app — see sample_target/README.md.

Every value below is fabricated for the scanner's tests to detect. None of
this is a real credential or real data.
"""

import logging

logger = logging.getLogger(__name__)

# --- PCAT-SECRET fixture: a fake AWS key ID and a fake generic credential ---
AWS_ACCESS_KEY_ID = "AKIAFAKEEXAMPLE00000"
db_password = "not-a-real-secret-fixture-value"

# A correctly-sourced credential (from the environment) should NOT be flagged.
import os
real_password = os.environ["DB_PASSWORD"]


def process_user(user_id: str, ssn: str) -> None:
    """PCAT-PII-LOG fixture: logs a PII-suggestive field name and a literal
    PII-shaped value in the same call."""
    logger.info("Processing user %s with ssn %s", user_id, ssn)
    print("Fallback contact: jane.doe@example.com")
