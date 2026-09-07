"""Synthetic fixture — see sample_target/README.md.

Exercises PCAT-ENCRYPT: a database connection with TLS explicitly disabled.
"""

DATABASE_URL = "postgresql://app_user:fixture-value@db.internal:5432/app?sslmode=disable"
