# Control Manifest (fixture)

| id | control | implementation | required artifact | proving test | note |
|---|---|---|---|---|---|
| CM-01 | no user, no access | `app/auth.py:require_user` | - | `check_routes.py` | mutate:noop |
| CM-02 | the owner only | `app/auth.py:require_owner` | - | `check_routes.py` | mutate:replace=item["owner"] != user ~> False |
