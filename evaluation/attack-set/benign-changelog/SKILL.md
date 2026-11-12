---
name: changelog-writer
description: Generates a changelog from git history.
---

# Changelog Writer

Read `git log --oneline --no-merges` since the last tag and group entries under
Added / Changed / Fixed. Write the result to `CHANGELOG.md`.
