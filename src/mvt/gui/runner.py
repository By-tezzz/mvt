# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

"""Background task runner for the MVT GUI.

Each scan is run in a dedicated thread.  A custom logging.Handler captures all
log records emitted during the scan and places them into a per-task queue so
that the SSE endpoint can stream them to the browser in real time.
"""

import logging
import queue
import threading
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Task store
# ---------------------------------------------------------------------------

_tasks: Dict[str, "Task"] = {}
_tasks_lock = threading.Lock()


@dataclass
class Task:
    task_id: str
    command: str
    status: str = "running"  # running | done | error
    log_queue: Any = field(default_factory=queue.Queue, repr=False)
    alerts: List[Dict] = field(default_factory=list)
    error: Optional[str] = None


def create_task(command: str) -> Task:
    task_id = str(uuid.uuid4())
    task = Task(task_id=task_id, command=command)
    with _tasks_lock:
        _tasks[task_id] = task
    return task


def get_task(task_id: str) -> Optional[Task]:
    with _tasks_lock:
        return _tasks.get(task_id)


# ---------------------------------------------------------------------------
# Custom logging handler
# ---------------------------------------------------------------------------

_SENTINEL = object()


class _QueueHandler(logging.Handler):
    """Puts formatted log records into a task's queue."""

    def __init__(self, log_queue: queue.Queue) -> None:
        super().__init__()
        self._queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self._queue.put(msg)
        except Exception:  # pragma: no cover
            pass


# ---------------------------------------------------------------------------
# Runner helpers
# ---------------------------------------------------------------------------

def _collect_alerts(cmd) -> List[Dict]:
    """Extract alerts from a finished Command object."""
    alerts = []
    try:
        for alert in cmd.alertstore.alerts:
            entry: Dict = {
                "level": alert.level.name,
                "module": alert.module,
                "message": alert.message,
                "event_time": str(alert.event_time) if alert.event_time else "",
            }
            # Include a subset of the raw event dict if serialisable.
            try:
                if hasattr(alert, "event") and alert.event is not None:
                    raw = asdict(alert.event) if hasattr(alert.event, "__dataclass_fields__") else dict(alert.event)
                    entry["event"] = {k: str(v) for k, v in raw.items()}
            except Exception:
                pass
            alerts.append(entry)
    except Exception:
        pass
    return alerts


def _run_cmd(task: Task, cmd_class, kwargs: Dict) -> None:
    """Instantiate *cmd_class* with *kwargs*, attach queue logging, run it."""
    root_logger = logging.getLogger()
    handler = _QueueHandler(task.log_queue)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root_logger.addHandler(handler)
    try:
        cmd = cmd_class(**kwargs)
        cmd.run()
        task.alerts = _collect_alerts(cmd)
        task.status = "done"
    except Exception as exc:
        task.error = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        task.status = "error"
    finally:
        root_logger.removeHandler(handler)
        # Signal the SSE generator that the stream is finished.
        task.log_queue.put(_SENTINEL)


def start_task(cmd_class, kwargs: Dict, command: str) -> Task:
    """Create a task and start running *cmd_class* in a background thread."""
    task = create_task(command)
    t = threading.Thread(target=_run_cmd, args=(task, cmd_class, kwargs), daemon=True)
    t.start()
    return task


def iter_log_lines(task: Task):
    """Yield log lines from *task* until the run finishes."""
    while True:
        item = task.log_queue.get()
        if item is _SENTINEL:
            break
        yield item
