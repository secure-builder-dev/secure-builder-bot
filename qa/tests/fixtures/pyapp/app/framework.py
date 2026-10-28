"""A ten-line fake web framework: a route table, a request, and a dispatcher that turns refusals into status codes."""
ROUTES: dict[str, object] = {}


class PermissionDenied(Exception):
    status = 403


class Request:
    def __init__(self, user=None):
        self.user = user


def route(path):
    def register(fn):
        ROUTES[path] = fn
        return fn
    return register


def handle(path, request, **params):
    try:
        return 200, ROUTES[path](request, **params)
    except PermissionDenied as e:
        return e.status, None
