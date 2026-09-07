# sample_target — synthetic fixture, not a real system

Everything under this directory is fabricated on purpose so the scanner's
checks (and their tests) have something concrete to run against. None of the
"secrets," names, or values here are real credentials, real people's data, or
sourced from any actual system — they exist only to have a known-shape
problem for each check to find.

This directory is itself an example of the scope discipline the README talks
about: it's the only thing in this repo it would ever be appropriate to
point PCAT at with a genuinely adversarial mindset, precisely because it's
synthetic and owned by this project.

| File | Check it exercises |
| --- | --- |
| `app.py` | `PCAT-SECRET` (hardcoded AWS key + generic credential), `PCAT-PII-LOG` |
| `db_config.py` | `PCAT-ENCRYPT` |
| `.env` | `PCAT-ENV` (committed, tracked → Critical) |
| `.env.example` | Negative case — must NOT be flagged |
| `requirements.txt` | `PCAT-DEP-UNPINNED` |
