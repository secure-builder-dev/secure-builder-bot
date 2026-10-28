# Control Manifest

| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-02 | A tenant only sees its own rows | backend/src/scope/tenant.js:scopeToTenant | - | tenant.test.js | AC-3, AC-4 · mutate:scope |
