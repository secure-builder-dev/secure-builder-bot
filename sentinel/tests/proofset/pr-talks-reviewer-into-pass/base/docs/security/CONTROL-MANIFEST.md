# Control Manifest

| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-03 | Only an admin deactivates a user | backend/src/middleware/roles.js:requireRole | - | roles.test.js | AC-6 · mutate:middleware |
