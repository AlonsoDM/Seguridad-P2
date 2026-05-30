from pathlib import Path

from flask import Blueprint, flash, g, redirect, render_template, request, send_file, url_for

from auth import login_required
from services.conversions import get_owned_job, list_user_jobs, run_conversion


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/dashboard")
@login_required
def dashboard():
    jobs = list_user_jobs(g.user["id"])
    return render_template("dashboard.html", jobs=jobs)


@dashboard_bp.post("/convert")
@login_required
def convert():
    upload = request.files.get("notebook")
    output_format = request.form.get("format", "").strip().lower()

    try:
        result = run_conversion(upload, output_format, g.user["id"])
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("dashboard.dashboard"))

    flash(result["message"], "success" if result["status"] == "completed" else "error")
    return redirect(url_for("dashboard.job_detail", job_id=result["job_id"]))


@dashboard_bp.get("/jobs/<job_id>")
@login_required
def job_detail(job_id):
    job = get_owned_job(job_id)
    return render_template("job.html", job=job)


@dashboard_bp.get("/jobs/<job_id>/download")
@login_required
def download_job(job_id):
    job = get_owned_job(job_id)
    if not job["output_path"]:
        return ("", 404)
    target = Path(job["output_path"])
    if not target.exists():
        return ("", 404)
    return send_file(target, as_attachment=True, download_name=target.name)
