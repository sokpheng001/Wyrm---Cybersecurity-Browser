"""Animated chrome widgets: top loading bar and the offline banner."""
from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QRectF, Qt, QTimer, QVariantAnimation
from PySide6.QtGui import QColor, QLinearGradient, QPainter
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QWidget


class LoadingBar(QWidget):
    """Thin progress line: eases toward real progress, trickles while waiting, shimmers, fades out."""

    COLOR = QColor("#1a73e8")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(3)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self._value = 0.0      # 0..1 drawn width
        self._target = 0.0
        self._opacity = 0.0
        self._phase = 0.0      # shimmer position
        self.active = False

        self._grow = QVariantAnimation(self)
        self._grow.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._grow.valueChanged.connect(self._set_value)

        self._fade = QVariantAnimation(self)
        self._fade.setDuration(350)
        self._fade.valueChanged.connect(self._set_opacity)
        self._fade.finished.connect(self._after_fade)

        self._tick = QTimer(self)
        self._tick.setInterval(16)  # ~60 fps shimmer + trickle
        self._tick.timeout.connect(self._on_tick)

    # ---------------------------------------------------------------- API
    def start(self):
        self.active = True
        self._fade.stop()
        self._set_opacity(1.0)
        self._value = 0.0
        self._target = 0.0
        self._animate_to(0.25, 300)
        self._tick.start()

    def set_progress(self, percent: int):
        if not self.active:
            self.start()
        t = min(0.95, max(self._target, percent / 100 * 0.95))
        if t > self._target + 0.01:
            self._animate_to(t, 250)

    def finish(self):
        if not self.active:
            return
        self.active = False
        self._animate_to(1.0, 220)
        self._grow.finished.connect(self._fade_out, Qt.ConnectionType.SingleShotConnection)

    def reset(self):
        self.active = False
        self._grow.stop()
        self._fade.stop()
        self._tick.stop()
        self._value = self._opacity = 0.0
        self.update()

    # ---------------------------------------------------------------- internals
    def _animate_to(self, target, ms):
        self._target = target
        self._grow.stop()
        self._grow.setDuration(ms)
        self._grow.setStartValue(self._value)
        self._grow.setEndValue(target)
        self._grow.start()

    def _on_tick(self):
        self._phase = (self._phase + 0.012) % 1.4
        # slow trickle so the bar never looks frozen on slow servers
        if self.active and self._grow.state() != QVariantAnimation.State.Running and self._target < 0.9:
            self._animate_to(self._target + (0.9 - self._target) * 0.06, 400)
        self.update()

    def _fade_out(self):
        self._fade.stop()
        self._fade.setStartValue(self._opacity)
        self._fade.setEndValue(0.0)
        self._fade.start()

    def _after_fade(self):
        if not self.active:
            self._tick.stop()
            self._value = 0.0
            self.update()

    def _set_value(self, v):
        self._value = float(v)
        self.update()

    def _set_opacity(self, v):
        self._opacity = float(v)
        self.update()

    def paintEvent(self, _e):
        if self._opacity <= 0 or self._value <= 0:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setOpacity(self._opacity)
        w = self.width() * self._value
        rect = QRectF(0, 0, w, self.height())
        p.fillRect(rect, self.COLOR)
        # moving highlight
        x = (self._phase - 0.2) * self.width()
        g = QLinearGradient(x, 0, x + self.width() * 0.2, 0)
        g.setColorAt(0.0, QColor(255, 255, 255, 0))
        g.setColorAt(0.5, QColor(255, 255, 255, 140))
        g.setColorAt(1.0, QColor(255, 255, 255, 0))
        p.fillRect(rect, g)
        # glowing head
        head = QColor(self.COLOR)
        head.setAlpha(120)
        p.fillRect(QRectF(max(0, w - 40), 0, 40, self.height()), head)
        p.end()


class OfflineBanner(QWidget):
    """Slides down under the toolbar while the network is unreachable."""

    def __init__(self, on_retry, parent=None):
        super().__init__(parent)
        self.setObjectName("OfflineBanner")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        row = QHBoxLayout(self)
        row.setContentsMargins(14, 6, 10, 6)
        self.label = QLabel("You're offline. Check your Wi-Fi or cable; pages will reload automatically when you're back.")
        row.addWidget(self.label, 1)
        btn = QPushButton("Try again")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(on_retry)
        row.addWidget(btn)
        self._full = 40
        self.setMaximumHeight(0)
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(260)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(lambda v: self.setMaximumHeight(int(v)))

    def set_offline(self, offline: bool, text: str | None = None):
        if text:
            self.label.setText(text)
        end = self._full if offline else 0
        if self.maximumHeight() == end:
            return
        self._anim.stop()
        self._anim.setStartValue(self.maximumHeight())
        self._anim.setEndValue(end)
        self._anim.start()
