# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

"""Flask application factory for the MVT GUI."""

import json
import time

from flask import Flask, Response, redirect, render_template, request, url_for

from mvt.android.cmd_check_androidqf import CmdAndroidCheckAndroidQF
from mvt.android.cmd_check_backup import CmdAndroidCheckBackup
from mvt.android.cmd_check_bugreport import CmdAndroidCheckBugreport
from mvt.android.cmd_check_intrusion_logs import CmdAndroidCheckIntrusionLogs
from mvt.common.updates import IndicatorsUpdates
from mvt.ios.cmd_check_backup import CmdIOSCheckBackup
from mvt.ios.cmd_check_fs import CmdIOSCheckFS
from mvt.ios.cmd_check_sysdiagnose import CmdIOSCheckSysdiagnose
from mvt.ios.decrypt import DecryptBackup

from .runner import get_task, iter_log_lines, start_task

# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.secret_key = "mvt-gui-secret"  # only needed for flash; no sensitive data

    # ------------------------------------------------------------------
    # Home
    # ------------------------------------------------------------------

    @app.route("/")
    def index():
        return render_template("index.html")

    # ------------------------------------------------------------------
    # Platform pages
    # ------------------------------------------------------------------

    @app.route("/ios")
    def ios():
        return render_template("ios.html")

    @app.route("/android")
    def android():
        return render_template("android.html")

    # ------------------------------------------------------------------
    # Run a scan
    # ------------------------------------------------------------------

    @app.route("/run", methods=["POST"])
    def run():
        data = request.form
        command = data.get("command", "")
        iocs = [p.strip() for p in data.get("iocs", "").splitlines() if p.strip()]
        output = data.get("output", "").strip() or None

        if command == "ios-check-backup":
            kwargs = dict(
                target_path=data["target_path"],
                results_path=output,
                ioc_files=iocs,
                module_options={"fast_mode": "fast" in data},
                hashes="hashes" in data,
                disable_version_check=True,
                disable_indicator_check=not iocs,
            )
            task = start_task(CmdIOSCheckBackup, kwargs, command)

        elif command == "ios-check-fs":
            kwargs = dict(
                target_path=data["target_path"],
                results_path=output,
                ioc_files=iocs,
                module_options={"fast_mode": "fast" in data},
                hashes="hashes" in data,
                disable_version_check=True,
                disable_indicator_check=not iocs,
            )
            task = start_task(CmdIOSCheckFS, kwargs, command)

        elif command == "ios-check-sysdiagnose":
            kwargs = dict(
                target_path=data["target_path"],
                results_path=output,
                ioc_files=iocs,
                hashes="hashes" in data,
                disable_version_check=True,
                disable_indicator_check=not iocs,
            )
            task = start_task(CmdIOSCheckSysdiagnose, kwargs, command)

        elif command == "android-check-bugreport":
            kwargs = dict(
                target_path=data["target_path"],
                results_path=output,
                ioc_files=iocs,
                hashes=True,
                disable_version_check=True,
                disable_indicator_check=not iocs,
            )
            task = start_task(CmdAndroidCheckBugreport, kwargs, command)

        elif command == "android-check-backup":
            password = data.get("backup_password", "").strip() or None
            kwargs = dict(
                target_path=data["target_path"],
                results_path=output,
                ioc_files=iocs,
                hashes=True,
                module_options={
                    "interactive": False,
                    "backup_password": password,
                },
                disable_version_check=True,
                disable_indicator_check=not iocs,
            )
            task = start_task(CmdAndroidCheckBackup, kwargs, command)

        elif command == "android-check-androidqf":
            password = data.get("backup_password", "").strip() or None
            kwargs = dict(
                target_path=data["target_path"],
                results_path=output,
                ioc_files=iocs,
                hashes="hashes" in data,
                module_options={
                    "interactive": False,
                    "backup_password": password,
                    "virustotal": False,
                    "virustotal_delay": 16,
                },
                disable_version_check=True,
                disable_indicator_check=not iocs,
            )
            task = start_task(CmdAndroidCheckAndroidQF, kwargs, command)

        elif command == "android-check-intrusion-logs":
            timezone = data.get("timezone", "").strip() or None
            module_options = {}
            if timezone:
                module_options["device_timezone"] = timezone
            kwargs = dict(
                target_path=data["target_path"],
                results_path=output,
                ioc_files=iocs,
                module_options=module_options if module_options else None,
                disable_version_check=True,
                disable_indicator_check=not iocs,
            )
            task = start_task(CmdAndroidCheckIntrusionLogs, kwargs, command)

        else:
            return {"error": f"Unknown command: {command}"}, 400

        return redirect(url_for("results", task_id=task.task_id))

    # ------------------------------------------------------------------
    # SSE log stream
    # ------------------------------------------------------------------

    @app.route("/stream/<task_id>")
    def stream(task_id):
        task = get_task(task_id)
        if task is None:
            return {"error": "task not found"}, 404

        def generate():
            for line in iter_log_lines(task):
                # SSE format
                yield f"data: {json.dumps({'line': line})}\n\n"
            # Send final status event so JS knows the run is over.
            yield f"data: {json.dumps({'done': True, 'status': task.status})}\n\n"

        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # ------------------------------------------------------------------
    # Results page
    # ------------------------------------------------------------------

    @app.route("/results/<task_id>")
    def results(task_id):
        task = get_task(task_id)
        if task is None:
            if request.args.get("json"):
                return {"error": "Task not found"}, 404
            return render_template("index.html", error="Task not found."), 404
        if request.args.get("json"):
            return {"alerts": task.alerts, "status": task.status, "error": task.error}
        return render_template("results.html", task=task)

    # ------------------------------------------------------------------
    # Download IOCs
    # ------------------------------------------------------------------

    @app.route("/download-iocs", methods=["POST"])
    def download_iocs():
        def generate():
            import io
            import logging

            buf = io.StringIO()

            class StreamHandler(logging.Handler):
                def emit(self, record):
                    buf.write(self.format(record) + "\n")

            handler = StreamHandler()
            handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
            root = logging.getLogger()
            root.addHandler(handler)
            try:
                ioc_updates = IndicatorsUpdates()
                ioc_updates.update()
                yield f"data: {json.dumps({'line': 'IOC download complete.'})}\n\n"
            except Exception as exc:
                yield f"data: {json.dumps({'line': f'Error: {exc}'})}\n\n"
            finally:
                root.removeHandler(handler)
                for line in buf.getvalue().splitlines():
                    yield f"data: {json.dumps({'line': line})}\n\n"
            yield f"data: {json.dumps({'done': True, 'status': 'done'})}\n\n"

        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return app
