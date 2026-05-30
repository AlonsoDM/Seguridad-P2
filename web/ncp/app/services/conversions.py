import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import abort, g

from db import BASE_DIR, JOBS_DIR, execute, fetch_all, fetch_one
from settings import setting_enabled


CONVERTER_SCRIPT = BASE_DIR / "app" / "converter" / "convert_job.py"
ALLOWED_FORMATS = {"html", "markdown"}


def list_user_jobs(user_id):
    return fetch_all(
        """
        SELECT jobs.id, jobs.original_filename, jobs.output_format,
               jobs.status, jobs.created_at
        FROM jobs
        WHERE jobs.user_id = ?
        ORDER BY jobs.created_at DESC
        """,
        (user_id,),
    )


def list_users_with_job_counts():
    return fetch_all(
        """
        SELECT users.id, users.username, users.role, COUNT(jobs.id) AS job_count
        FROM users
        LEFT JOIN jobs ON jobs.user_id = users.id
        GROUP BY users.id, users.username, users.role
        ORDER BY users.role DESC, users.username ASC
        """
    )


def get_owned_job(job_id):
    job = fetch_one("SELECT * FROM jobs WHERE id = ?", (job_id,))
    if not job:
        abort(404)
    if g.user["role"] != "admin" and job["user_id"] != g.user["id"]:
        abort(403)
    return job


def validate_conversion_request(upload, output_format):
    if upload is None or not upload.filename:
        raise ValueError("Choose a notebook file first.")

    if output_format not in ALLOWED_FORMATS:
        raise ValueError("Unsupported conversion format.")

    filename = Path(upload.filename).name
    if Path(filename).suffix.lower() != ".ipynb":
        raise ValueError("Only .ipynb uploads are accepted.")

    return filename


def determine_storage_mode(output_format):
    if output_format == "markdown":
        return "saved_assets" if setting_enabled("asset_storage_enabled") else "single_file"
    return "single_file"


def create_job_paths(job_id):
    job_root = JOBS_DIR / job_id
    incoming_dir = job_root / "incoming"
    exports_dir = job_root / "exports"
    incoming_dir.mkdir(parents=True, exist_ok=True)
    exports_dir.mkdir(parents=True, exist_ok=True)
    return incoming_dir, exports_dir


def insert_job_record(
    job_id,
    user_id,
    filename,
    output_format,
    status,
    upload_path,
    output_path,
):
    execute(
        """
        INSERT INTO jobs (
            id, user_id, original_filename, output_format,
            status, upload_path, output_path, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            job_id,
            user_id,
            filename,
            output_format,
            status,
            str(upload_path),
            output_path,
            datetime.now(timezone.utc).isoformat(),
        ),
    )


def run_conversion(upload, output_format, user_id):
    filename = validate_conversion_request(upload, output_format)

    job_id = uuid.uuid4().hex[:12]
    incoming_dir, exports_dir = create_job_paths(job_id)
    upload_path = incoming_dir / filename
    upload.save(upload_path)

    storage_mode = determine_storage_mode(output_format)

    try:
        completed = subprocess.run(
            [
                sys.executable,
                str(CONVERTER_SCRIPT),
                "--input",
                str(upload_path),
                "--output-dir",
                str(exports_dir),
                "--format",
                output_format,
                "--storage-mode",
                storage_mode,
            ],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=90,
        )
    except subprocess.TimeoutExpired:
        insert_job_record(
            job_id=job_id,
            user_id=user_id,
            filename=filename,
            output_format=output_format,
            status="failed",
            upload_path=upload_path,
            output_path=None,
        )
        return {"job_id": job_id, "status": "failed", "message": "Conversion timed out."}

    output_path = None
    status = "failed"
    if completed.returncode == 0:
        try:
            converter_payload = json.loads(completed.stdout.strip())
            output_path = converter_payload["output_path"]
            status = "completed"
        except (json.JSONDecodeError, KeyError):
            status = "failed"

    insert_job_record(
        job_id=job_id,
        user_id=user_id,
        filename=filename,
        output_format=output_format,
        status=status,
        upload_path=upload_path,
        output_path=output_path,
    )

    message = "Conversion completed." if status == "completed" else "Conversion failed. Please try again."
    return {"job_id": job_id, "status": status, "message": message}
