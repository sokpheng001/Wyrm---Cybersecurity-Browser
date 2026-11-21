/*
 * Wyrm — wyrm/qml/Main.qml
 * Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
 * Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
 * Authors: @oda, @sopi, @kwan
 */
import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts
import QtWebEngine

ApplicationWindow {
    id: win
    width: 1280
    height: 820
    visible: true
    title: "Wyrm"
    color: pal.bg

    // palette pulled from the existing Python theme (IBM Carbon colors), square design
    QtObject {
        id: pal
        readonly property color bg: bridge.palette.bg || "#161616"
        readonly property color layer: bridge.palette.layer || "#262626"
        readonly property color layer2: bridge.palette.layer2 || "#393939"
        readonly property color hover: bridge.palette.hover || "#333333"
        readonly property color text: bridge.palette.text || "#f4f4f4"
        readonly property color muted: bridge.palette.muted || "#c6c6c6"
        readonly property color border: bridge.palette.border || "#393939"
        readonly property color accent: bridge.palette.interactive || "#0f62fe"
    }

    ListModel { id: tabs }
    property int current: -1

    function activeView() {
        return (current >= 0 && current < viewRepeater.count) ? viewRepeater.itemAt(current) : null
    }
    function newTab(url) {
        tabs.append({ title: "New tab", url: url || bridge.homeUrl })
        current = tabs.count - 1
    }
    function closeTab(i) {
        if (tabs.count <= 1) { tabs.setProperty(0, "url", bridge.homeUrl); return }
        tabs.remove(i)
        if (current >= tabs.count) current = tabs.count - 1
    }
    Component.onCompleted: newTab(bridge.homeUrl)

    // ---------------------------------------------------------------- chrome
    header: Rectangle {
        color: pal.layer
        implicitHeight: tabStrip.height + toolbar.height + 1
        Column {
            width: parent.width
            // tab strip
            Row {
                id: tabStrip
                width: parent.width
                height: 40
                spacing: 1
                Repeater {
                    model: tabs
                    delegate: Rectangle {
                        width: 200; height: 40
                        color: index === win.current ? pal.bg : pal.layer
                        Rectangle { // top accent on the active tab
                            width: parent.width; height: 2; visible: index === win.current; color: pal.accent
                        }
                        MouseArea { anchors.fill: parent; onClicked: win.current = index }
                        Row {
                            anchors.fill: parent
                            anchors.leftMargin: 12; anchors.rightMargin: 6
                            spacing: 6
                            Text {
                                width: parent.width - 34
                                anchors.verticalCenter: parent.verticalCenter
                                text: model.title
                                elide: Text.ElideRight
                                color: index === win.current ? pal.text : pal.muted
                                font.pixelSize: 13
                            }
                            ToolButton {
                                anchors.verticalCenter: parent.verticalCenter
                                width: 22; height: 22
                                contentItem: Text { text: "✕"; color: pal.muted; font.pixelSize: 12
                                    horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter }
                                background: Rectangle { radius: 0; color: parent.hovered ? pal.hover : "transparent" }
                                onClicked: win.closeTab(index)
                            }
                        }
                    }
                }
                ToolButton {
                    width: 40; height: 40
                    contentItem: Text { text: "+"; color: pal.text; font.pixelSize: 18
                        horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter }
                    background: Rectangle { color: parent.hovered ? pal.hover : pal.layer }
                    onClicked: win.newTab(bridge.homeUrl)
                }
            }
            // toolbar: nav + address
            Rectangle {
                id: toolbar
                width: parent.width; height: 48; color: pal.layer
                Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: pal.border }
                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 8; anchors.rightMargin: 8
                    spacing: 2
                    component NavBtn: ToolButton {
                        Layout.preferredWidth: 36; Layout.preferredHeight: 36
                        property string glyph: ""
                        contentItem: Text { text: parent.glyph; color: parent.enabled ? pal.text : pal.muted
                            font.pixelSize: 16; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter }
                        background: Rectangle { color: parent.hovered ? pal.hover : "transparent" }
                    }
                    NavBtn { glyph: "←"; onClicked: { var v = win.activeView(); if (v && v.view.canGoBack) v.view.goBack() } }
                    NavBtn { glyph: "→"; onClicked: { var v = win.activeView(); if (v && v.view.canGoForward) v.view.goForward() } }
                    NavBtn { glyph: "⟳"; onClicked: { var v = win.activeView(); if (v) v.view.reload() } }
                    NavBtn { glyph: "⌂"; onClicked: { var v = win.activeView(); if (v) v.view.url = bridge.homeUrl } }

                    // address pill
                    Rectangle {
                        Layout.fillWidth: true; Layout.preferredHeight: 36
                        color: pal.bg
                        border.color: address.activeFocus ? pal.accent : pal.border
                        border.width: address.activeFocus ? 2 : 1
                        Row {
                            anchors.fill: parent; anchors.leftMargin: 12; spacing: 8
                            Text { anchors.verticalCenter: parent.verticalCenter; text: "⌕"; color: pal.muted; font.pixelSize: 15 }
                            TextField {
                                id: address
                                width: parent.width - 30
                                anchors.verticalCenter: parent.verticalCenter
                                color: pal.text
                                font.pixelSize: 14
                                background: null
                                placeholderText: "Search, or type a URL, CVE-ID or domain"
                                placeholderTextColor: pal.muted
                                selectByMouse: true
                                text: { var v = win.activeView(); return v ? v.shownUrl : "" }
                                onAccepted: {
                                    var v = win.activeView()
                                    if (v) v.view.url = bridge.resolve(text)
                                }
                            }
                        }
                    }
                    NavBtn { glyph: "⛉"; onClicked: panel.open = !panel.open }  // security panel toggle
                    NavBtn { glyph: "⋮" }
                }
                // loading progress
                Rectangle {
                    anchors.bottom: parent.bottom
                    height: 2
                    color: pal.accent
                    property var v: win.activeView()
                    visible: v && v.view.loading
                    width: (v ? v.view.loadProgress / 100 : 0) * parent.width
                }
            }
        }
    }

    // ---------------------------------------------------------------- content + side panel
    RowLayout {
        anchors.fill: parent
        spacing: 0
        StackLayout {
            Layout.fillWidth: true; Layout.fillHeight: true
            currentIndex: win.current
            Repeater {
                id: viewRepeater
                model: tabs
                delegate: Item {
                    property alias view: web
                    property string shownUrl: web.url == bridge.homeUrl ? "" : web.url
                    WebEngineView {
                        id: web
                        anchors.fill: parent
                        url: model.url
                        onTitleChanged: tabs.setProperty(index, "title", title || "New tab")
                    }
                }
            }
        }
        // collapsible security panel (placeholder proving the layout; real tabs port next)
        Rectangle {
            id: panel
            property bool open: false
            Layout.preferredWidth: open ? 320 : 0
            Layout.fillHeight: true
            visible: open
            color: pal.layer
            Behavior on Layout.preferredWidth { NumberAnimation { duration: 160; easing.type: Easing.OutCubic } }
            Rectangle { width: 1; height: parent.height; color: pal.border }
            Column {
                anchors.fill: parent; anchors.margins: 16; spacing: 12
                Text { text: "SECURITY"; color: pal.muted; font.pixelSize: 11; font.bold: true; font.letterSpacing: 1.2 }
                Text { text: "Shields · Overview · Traffic · Intruder · DOM · Findings"
                    color: pal.text; font.pixelSize: 13; wrapMode: Text.WordWrap; width: parent.width }
                Text { text: "QML chrome prototype — the Python security backend plugs in here unchanged."
                    color: pal.muted; font.pixelSize: 12; wrapMode: Text.WordWrap; width: parent.width }
            }
        }
    }

    footer: Rectangle {
        height: 22; color: pal.layer
        Text { anchors.verticalCenter: parent.verticalCenter; anchors.left: parent.left; anchors.leftMargin: 10
            text: "Wyrm " + bridge.version + " · QML prototype"; color: pal.muted; font.pixelSize: 11 }
    }
}
