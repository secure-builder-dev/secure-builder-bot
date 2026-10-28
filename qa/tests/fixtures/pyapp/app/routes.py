from app.auth import require_owner, require_user
from app.framework import route

ITEMS = {"1": {"owner": "alice", "name": "one"}, "2": {"owner": "bob", "name": "two"}}


@route("/items/{id}")
def get_item(request, id):
    user = require_user(request)
    return require_owner(user, ITEMS[id])
