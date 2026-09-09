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
| `.env` | `PCAT-ENV` (committed, tracked → Critical); also `PCAT-PERM` on POSIX only — see note below |
| `.env.example` | Negative case for both `PCAT-ENV` and `PCAT-PERM` — must NOT be flagged by either |
| `requirements.txt` | `PCAT-DEP-UNPINNED` |

**Why `.env` trips a second check on POSIX:** git only tracks a file's executable
bit, not its read/write permission bits, so a fresh clone always gets the
umask-default mode (typically world-readable) regardless of what was
committed — there's no way to make `.env` "checked out as chmod 600" via git
alone. `PCAT-PERM` picking that up isn't a fixture bug: a committed secrets
file that's also world-readable really is one more genuine finding. This is a
no-op on native Windows (POSIX mode bits don't exist there), which is why the
total finding count in `tests/test_engine_report.py` is platform-conditional.
