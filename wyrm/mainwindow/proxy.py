#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/proxy.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Developers: Kwan and Oda (intercepting HTTPS proxy)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Enable/disable the startup MITM proxy (wyrm/security/mitm.py). The flow history + response interception UI
lives in the ProxyTab panel. (Mixed into MainWindow.)"""
from __future__ import annotations


class ProxyMixin:
    def mitm_active(self) -> bool:
        from ..security import mitm
        return mitm.ACTIVE is not None

    # ---------------------------------------------------------------- enable / disable (needs restart)
    def set_mitm_enabled(self, on: bool):
        from ..security import mitm
        from ..ui.dialogs import ask
        self.settings.setValue("mitm/enabled", bool(on))
        if on:
            ca = mitm.CertAuthority(self.data_dir / "mitm")
            ok = mitm.install_ca(ca.ca_cert_path)
            msg = ("Intercepting proxy will start when you restart Wyrm. Its certificate authority was "
                   "installed so HTTPS pages are decrypted for capture." if ok else
                   "Couldn't install the certificate automatically. The proxy will still start on restart, but "
                   f"HTTPS sites may show certificate warnings. The CA file is at:\n{ca.ca_cert_path}")
        else:
            mitm.uninstall_ca()
            msg = "Intercepting proxy will be off after you restart Wyrm (its certificate was removed)."
        restart, _ = ask(self, "Restart to apply", msg + "\n\nRestart Wyrm now?", "Restart now", cancel="Later")
        if restart:
            self._restart_app()

    def _restart_app(self):
        import sys
        from PySide6.QtCore import QProcess
        from PySide6.QtWidgets import QApplication
        self._save_session() if hasattr(self, "_save_session") else None
        for w in QApplication.topLevelWidgets():
            w._force_close = True
        QProcess.startDetached(sys.executable, sys.argv[1:] if getattr(sys, "frozen", False) else sys.argv)
        QApplication.instance().quit()
