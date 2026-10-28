# Control Manifest

| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-01 | Only a signed-in user reaches a route | backend/src/middleware/auth.js:requireAuth | - | auth.test.js | AC-3 · mutate:middleware |
