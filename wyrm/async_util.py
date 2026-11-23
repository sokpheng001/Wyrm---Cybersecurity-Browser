#------------------------------------------------------------------------------
# Wyrm — wyrm/async_util.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Run blocking work (HTTP calls) off the UI thread and deliver results back on it."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import QObject, Qt, Signal, Slot


class Runner(QObject):
    _done = Signal(object, object, object)  # callback, ok, result

    def __init__(self, workers: int = 4):
        super().__init__()
        self._pool = ThreadPoolExecutor(max_workers=workers)
        self._done.connect(self._dispatch, Qt.ConnectionType.QueuedConnection)

    def run(self, fn, callback, *args):
        """Call fn(*args) in a worker thread, then callback(ok, result_or_exception) on the UI thread."""
        def task():
            try:
                res = (True, fn(*args))
            except Exception as e:  # noqa: BLE001 - surfaced to the UI
                res = (False, e)
            self._done.emit(callback, *res)

        self._pool.submit(task)

    @Slot(object, object, object)
    def _dispatch(self, callback, ok, result):
        callback(ok, result)

    def shutdown(self):
        self._pool.shutdown(wait=False, cancel_futures=True)
