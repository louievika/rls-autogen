# Rules for assistants

- This repository is one migration, one test script and its documentation. Keep it that way.
- Run `test/verify.sql` against a throwaway database before proposing any change to the migration. Every check must pass.
- No secrets, keys, connection strings, project references or email addresses in any file or commit.
- Use generic names (`demo_*`) in examples and tests.
- Do not add dependencies, build steps or references to other projects.
