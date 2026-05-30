from functools import wraps

from flask import abort, g, redirect, session, url_for

from db import fetch_one


def load_current_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is None:
        return
    g.user = fetch_one(
        "SELECT id, username, password, role FROM users WHERE id = ?",
        (user_id,),
    )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("public.login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("public.login"))
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped
