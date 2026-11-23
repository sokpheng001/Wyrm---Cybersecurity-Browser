#------------------------------------------------------------------------------
# Wyrm — wyrm/widgets.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Animated chrome widgets: top loading bar, offline banner, and a centered busy spinner."""
from __future__ import annotations

import math

from PySide6.QtCore import QEasingCurve, QEvent, QPoint, QRect, QRectF, QSize, Qt, QTimer, QVariantAnimation, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QApplication, QBoxLayout, QHBoxLayout, QLabel, QLayout, QPushButton, QSizePolicy, QWidget,
)


class BusyOverlay(QWidget):
    """A centered spinning arc + label, overlaid on its parent while an async tool runs.

    Use: overlay = BusyOverlay(result_widget); overlay.start("Running…"); overlay.stop() when done.
    It covers the parent (blocking clicks), follows the parent's size, and uses the accent colour.
    """

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self._angle = 0
        self._phase = 0.0
        self._label = "Loading…"
        self._timer = QTimer(self)
        self._timer.setInterval(16)  # ~60fps
        self._timer.timeout.connect(self._tick)
        parent.installEventFilter(self)  # follow parent resize
        self.hide()

    def eventFilter(self, obj, ev):
        if obj is self.parent() and ev.type() in (QEvent.Type.Resize, QEvent.Type.Move):
            self.setGeometry(self.parent().rect())
        return False

    def start(self, label: str = "Working…"):
        self._label = label
        self.setGeometry(self.parent().rect())
        self.show()
        self.raise_()
        if not self._timer.isActive():
            self._timer.start()

    def stop(self):
        self._timer.stop()
        self.hide()

    def _tick(self):
        self._angle = (self._angle + 6) % 360
        self._phase = (self._phase + 0.05) % (2 * math.pi)
        self.update()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        # faint scrim so the spinner reads over any content
        scrim = self.palette().color(self.backgroundRole())
        scrim.setAlpha(150)
        p.fillRect(self.rect(), scrim)
        accent = QApplication.palette().highlight().color()  # matches blue/red mode
        cx, cy = self.width() / 2, self.height() / 2 - 10
        pulse = 0.5 + 0.5 * math.sin(self._phase)      # 0..1 pulse
        r = 16 + 3 * pulse                              # ring gently pulses in size
        # pulsing halo
        halo = QColor(accent)
        halo.setAlpha(int(40 * (1 - pulse)))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(halo)
        p.drawEllipse(QRectF(cx - r - 8, cy - r - 8, 2 * (r + 8), 2 * (r + 8)))
        # track + spinning arc
        track = QColor(accent)
        track.setAlpha(45)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(track, 3))
        p.drawEllipse(QRectF(cx - r, cy - r, 2 * r, 2 * r))
        arc = QColor(accent)
        arc.setAlpha(int(160 + 95 * pulse))            # arc opacity pulses too
        pen = QPen(arc, 3)  # (QPen(..., cap=...) keyword is not supported by PySide6: set it explicitly)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawArc(QRectF(cx - r, cy - r, 2 * r, 2 * r), -self._angle * 16, 110 * 16)
        # spinner only — no text label (clean, like modern loaders)
        p.end()


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


class InfoBanner(QWidget):
    """A bar that slides down under the toolbar with a message, one main action and a close button
    (e.g. "Add this extension to Wyrm Browser" on Chrome Web Store pages). Drawn by Wyrm, not the page."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("InfoBanner")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        row = QHBoxLayout(self)
        row.setContentsMargins(14, 6, 10, 6)
        self.label = QLabel("")
        self.label.setTextFormat(Qt.TextFormat.RichText)
        row.addWidget(self.label, 1)
        self.button = QPushButton("")
        self.button.setObjectName("Primary")
        self.button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.button.clicked.connect(lambda: self._action and self._action())
        row.addWidget(self.button)
        close = QPushButton("✕")
        close.setFixedWidth(32)
        close.setToolTip("Hide")
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.clicked.connect(lambda: self.show_banner(False))
        row.addWidget(close)
        self._action = None
        self._full = 44
        self.setMaximumHeight(0)
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(240)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(lambda v: self.setMaximumHeight(int(v)))

    def show_banner(self, show: bool, text: str = "", button: str = "", action=None):
        if show:
            self.label.setText(text)
            self.button.setText(button)
            self._action = action
        end = self._full if show else 0
        if self.maximumHeight() == end:
            return
        self._anim.stop()
        self._anim.setStartValue(self.maximumHeight())
        self._anim.setEndValue(end)
        self._anim.start()


class WrapRow(QLayout):
    """A horizontal row that wraps onto more lines when it runs out of width (responsive button/filter bars).
    On a line that fits, it behaves like QHBoxLayout: spare width goes to horizontally-expanding widgets
    (e.g. a filter box); items are vertically centred."""

    def __init__(self, hspacing=8, vspacing=8):
        # no parent here: attach with widget.setLayout() once the Python side is fully initialised
        super().__init__()
        self._items = []
        self._h, self._v = hspacing, vspacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, i):
        return self._items[i] if 0 <= i < len(self._items) else None

    def takeAt(self, i):
        return self._items.pop(i) if 0 <= i < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        try:
            return self._layout(QRect(0, 0, width, 0), apply=False)
        except Exception:  # noqa: BLE001 - an exception escaping into Qt's C++ layout code crashes the app
            return self.sizeHint().height()

    def setGeometry(self, rect):
        super().setGeometry(rect)
        try:
            self._layout(rect, apply=True)
        except Exception:  # noqa: BLE001
            pass

    def sizeHint(self):
        vis = self._visible()
        w = sum(self._w(it) for it in vis) + self._h * max(0, len(vis) - 1)
        h = max((it.sizeHint().height() for it in vis), default=0)
        m = self.contentsMargins()
        return QSize(w + m.left() + m.right(), h + m.top() + m.bottom())

    def minimumSize(self):  # as narrow as the widest single item
        vis = self._visible()
        w = max((max(it.minimumSize().width(), min(self._w(it), 160)) for it in vis), default=0)
        h = max((it.sizeHint().height() for it in vis), default=0)
        m = self.contentsMargins()
        return QSize(w + m.left() + m.right(), h + m.top() + m.bottom())

    def _visible(self):
        return [it for it in self._items if it.widget() is not None and not it.widget().isHidden()]

    @staticmethod
    def _w(it):
        return max(it.minimumSize().width(), min(it.sizeHint().width(), it.maximumSize().width()))

    _EXPAND = QSizePolicy.PolicyFlag.ExpandFlag.value

    @classmethod
    def _expands(cls, it, vertical=False):
        sp = it.widget().sizePolicy()
        pol = sp.verticalPolicy() if vertical else sp.horizontalPolicy()
        return bool(pol.value & cls._EXPAND)  # (enum & enum is not supported in PySide6)

    def _layout(self, rect, apply):
        m = self.contentsMargins()
        r = rect.adjusted(m.left(), m.top(), -m.right(), -m.bottom())
        lines, line, used = [], [], 0
        for it in self._visible():
            w = min(self._w(it), r.width())
            if line and used + self._h + w > r.width():
                lines.append((line, used))
                line, used = [], 0
            used += (self._h if line else 0) + w
            line.append((it, w))
        if line:
            lines.append((line, used))
        y = r.y()
        for line, used in lines:
            lh = max(it.sizeHint().height() for it, _ in line)
            grow = [i for i, (it, _) in enumerate(line) if self._expands(it)]
            extra = (r.width() - used) // len(grow) if grow else 0
            x = r.x()
            for i, (it, w) in enumerate(line):
                w = w + (extra if i in grow else 0)
                h = lh if self._expands(it, vertical=True) else min(it.sizeHint().height(), lh)
                if apply:
                    it.setGeometry(QRect(QPoint(x, y + (lh - h) // 2), QSize(w, h)))
                x += w + self._h
            y += lh + self._v
        return y - self._v - r.y() + m.top() + m.bottom() if lines else 0


_WRAP_ROWS: list = []


def make_rows_wrap(root: QWidget, wider_than: int = 280) -> int:
    """Turn every plain widget row (QHBoxLayout of widgets) under `root` that needs more than `wider_than` px
    into a WrapRow, so it wraps instead of forcing its page wider than the panel. Returns rows converted."""
    done = 0
    for row in root.findChildren(QHBoxLayout):
        parent = row.parent()
        if not isinstance(parent, QBoxLayout) or row.minimumSize().width() <= wider_than:
            continue
        items = [row.itemAt(i) for i in range(row.count())]
        if any(it.layout() is not None for it in items):  # nested layouts: leave alone
            continue
        idx = next((i for i in range(parent.count()) if parent.itemAt(i).layout() is row), -1)
        if idx < 0:
            continue
        holder = QWidget()
        holder.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        flow = WrapRow(hspacing=max(6, row.spacing()))
        _WRAP_ROWS.append((holder, flow))  # keep the Python objects alive: Qt calls their overridden methods
        while row.count():
            it = row.takeAt(0)
            wd = it.widget()
            if wd is not None:
                if wd.inherits("QLineEdit") and wd.minimumWidth() < 180:
                    wd.setMinimumWidth(180)  # filter boxes stay usable; neighbours wrap instead
                flow.addWidget(wd)
        holder.setLayout(flow)
        parent.takeAt(idx)
        parent.insertWidget(idx, holder)
        row.deleteLater()
        done += 1
    return done


class ModeChip(QWidget):
    """Red / Blue team pill in the tab strip: a soft breathing glow in the mode colour plus a light sheen that
    sweeps across every few seconds, so the current mode is obvious; hover / press states show it's clickable."""
    clicked = Signal()
    GLOW = 5  # px reserved around the pill for the glow

    def __init__(self, parent=None):
        super().__init__(parent)
        self._text, self._color = "", QColor("#0f62fe")
        self._t, self._hover, self._down = 0.0, False, False
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover)
        self.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        f = QFont(self.font())
        f.setPixelSize(11)
        f.setWeight(QFont.Weight.Bold)
        f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.6)
        self._font = f
        self._anim = QVariantAnimation(self, startValue=0.0, endValue=1.0, duration=3600, loopCount=-1)
        self._anim.valueChanged.connect(self._tick)
        self._anim.start()

    def set_mode(self, text: str, color: str):
        self._text, self._color = text, QColor(color)
        self.updateGeometry()
        self.update()

    def _tick(self, v):
        self._t = float(v)
        self.update()

    def sizeHint(self):
        fm = QFontMetrics(self._font)
        return QSize(fm.horizontalAdvance(self._text) + 26 + 2 * self.GLOW, 24 + 2 * self.GLOW)

    minimumSizeHint = sizeHint

    def event(self, e):
        t = e.type()
        if t == QEvent.Type.HoverEnter:
            self._hover = True
            self.update()
        elif t == QEvent.Type.HoverLeave:
            self._hover = self._down = False
            self.update()
        return super().event(e)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._down = True
            self.update()

    def mouseReleaseEvent(self, e):
        was = self._down
        self._down = False
        self.update()
        if was and self.rect().contains(e.position().toPoint()):
            self.clicked.emit()

    def keyPressEvent(self, e):
        if e.key() in (Qt.Key.Key_Space, Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.clicked.emit()
        else:
            super().keyPressEvent(e)

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        g = self.GLOW
        r = QRectF(self.rect()).adjusted(g, g, -g, -g)
        rad = r.height() / 2
        pulse = 0.5 - 0.5 * math.cos(2 * math.pi * self._t)          # 0..1..0 breathing
        boost = 1.5 if self._hover else 1.0
        p.setPen(Qt.PenStyle.NoPen)
        for grow, alpha in ((g, 0.07), (g * 0.6, 0.13), (g * 0.25, 0.22)):  # soft halo
            c = QColor(self._color)
            c.setAlphaF(min(1.0, alpha * (0.35 + 0.65 * pulse) * boost))
            p.setBrush(c)
            p.drawRoundedRect(r.adjusted(-grow, -grow, grow, grow), rad + grow, rad + grow)
        fill = QColor(self._color)
        fill = fill.darker(115) if self._down else (fill.lighter(112) if self._hover else fill)
        p.setBrush(fill)
        p.drawRoundedRect(r, rad, rad)
        # light sheen sweeping across the pill during the first part of each cycle
        if self._t < 0.45:
            path = QPainterPath()
            path.addRoundedRect(r, rad, rad)
            p.save()
            p.setClipPath(path)
            x = r.left() - 30 + (r.width() + 60) * (self._t / 0.45)
            grad = QLinearGradient(x - 22, 0, x + 22, 0)
            for stop, a in ((0.0, 0.0), (0.5, 0.38), (1.0, 0.0)):
                c = QColor(255, 255, 255)
                c.setAlphaF(a)
                grad.setColorAt(stop, c)
            p.fillRect(QRectF(x - 22, r.top(), 44, r.height()), grad)
            p.restore()
        if self.hasFocus():
            p.setPen(QPen(QColor(255, 255, 255, 200), 1.5))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(r.adjusted(1, 1, -1, -1), rad - 1, rad - 1)
        p.setPen(QColor("#ffffff"))
        p.setFont(self._font)
        p.drawText(r, Qt.AlignmentFlag.AlignCenter, self._text)
        p.end()

