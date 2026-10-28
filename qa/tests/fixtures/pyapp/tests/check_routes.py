import app.routes  # registers the route table
from app.framework import Request, handle


def test_owner_reads_their_item():
    assert handle("/items/{id}", Request("alice"), id="1") == (200, app.routes.ITEMS["1"])


def test_unauthenticated_request_is_refused_with_403():
    assert handle("/items/{id}", Request(None), id="1") == (403, None)


def test_user_a_cannot_read_user_b_item():
    assert handle("/items/{id}", Request("alice"), id="2") == (403, None)
