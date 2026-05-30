from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for

from db import execute, fetch_one

public_bp = Blueprint("public", __name__)

@public_bp.route("/", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = fetch_one(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (username,),
        )
        if not user or user["password"] != password:
            flash("Invalid credentials.", "error")
        else:
            session["user_id"] = user["id"]
            flash(f"Signed in as {user['username']}.", "success")
            return redirect(url_for("dashboard.dashboard"))

    return render_template("login.html")


@public_bp.post("/register")
def register():
    if g.user:
        return redirect(url_for("dashboard.dashboard"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if len(username) < 3:
        flash("Username must be at least 3 characters.", "error")
        return redirect(url_for("public.login"))

    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("public.login"))

    if password != confirm_password:
        flash("Passwords do not match.", "error")
        return redirect(url_for("public.login"))

    existing = fetch_one("SELECT id FROM users WHERE username = ?", (username,))
    if existing:
        flash("That username is already taken.", "error")
        return redirect(url_for("public.login"))

    execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (username, password, "user"),
    )
    flash("Account created. You can sign in now.", "success")
    return redirect(url_for("public.login"))


@public_bp.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("public.login"))
