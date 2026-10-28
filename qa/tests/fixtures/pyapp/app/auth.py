from app.framework import PermissionDenied


def require_user(request):
    """The first control: no user, no access."""
    if request.user is None:
        raise PermissionDenied("sign in first")
    return request.user


def require_owner(user, item):
    if item["owner"] != user:
        raise PermissionDenied("not yours")
    return item
