from flask import Blueprint, flash, render_template, request, redirect, url_for

from auth import admin_required
from services.conversions import list_users_with_job_counts
from settings import set_asset_storage_enabled


admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin", methods=["GET", "POST"])
@admin_required
def admin_panel():
    if request.method == "POST":
        enabled = request.form.get("asset_storage_enabled") == "on"
        set_asset_storage_enabled(enabled)
        flash("Settings updated.", "success")
        return redirect(url_for("admin.admin_panel"))

    users = list_users_with_job_counts()
    return render_template("admin.html", users=users)
