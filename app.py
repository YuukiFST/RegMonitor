import sys
import json
import zmq
import datetime
import csv
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QTableView, QLabel, QLineEdit, QFileDialog, 
    QMessageBox, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import Qt, QAbstractTableModel, QThread, pyqtSignal, QTimer

# Constants
ZMQ_ENDPOINT = "tcp://127.0.0.1:5555"

class RegistryTableModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self.headers = ["Timestamp", "Type", "Key Path", "Value Name", "Data Type", "Old Value", "New Value"]
        self.events = []

    def rowCount(self, parent=None):
        return len(self.events)

    def columnCount(self, parent=None):
        return len(self.headers)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        
        event = self.events[index.row()]
        col = index.column()
        
        if col == 0: return event.get("timestamp")
        if col == 1: return event.get("change_type")
        if col == 2: return event.get("key_path")
        if col == 3: return event.get("value_name")
        if col == 4: return event.get("data_type")
        if col == 5: return str(event.get("old_value", ""))
        if col == 6: return str(event.get("new_value", ""))
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.headers[section]
        return None

    def add_events(self, new_events):
        from PyQt6.QtCore import QModelIndex
        self.beginInsertRows(QModelIndex(), len(self.events), len(self.events) + len(new_events) - 1)
        self.events.extend(new_events)
        # Keep only last 5000 events for performance
        if len(self.events) > 5000:
            overflow = len(self.events) - 5000
            self.events = self.events[overflow:]
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self.events = []
        self.endResetModel()

class ZMQSubscriberThread(QThread):
    events_received = pyqtSignal(list)
    stats_updated = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.running = False
        self.context = zmq.Context()
        self.subscriber = self.context.socket(zmq.SUB)

    def run(self):
        self.subscriber.connect(ZMQ_ENDPOINT)
        self.subscriber.setsockopt_string(zmq.SUBSCRIBE, "")
        self.running = True
        
        while self.running:
            try:
                # Use poller to avoid blocking indefinitely and allow graceful shutdown
                if self.subscriber.poll(100):
                    message = self.subscriber.recv_json()
                    events = message.get("events", [])
                    if events:
                        self.events_received.emit(events)
                        self.stats_updated.emit(len(events))
            except Exception as e:
                print(f"ZMQ Error: {e}")
                self.msleep(100)

    def stop(self):
        self.running = False
        self.wait()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Registry Monitor")
        self.resize(1200, 800)

        self.total_changes = 0
        self.filtered_count = 0
        self.start_time = None
        self.monitoring = False

        self.init_ui()
        self.init_worker()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Controls
        ctrl_layout = QHBoxLayout()
        self.btn_toggle = QPushButton("Start Monitoring")
        self.btn_toggle.clicked.connect(self.toggle_monitoring)
        ctrl_layout.addWidget(self.btn_toggle)

        self.btn_clear = QPushButton("Clear")
        self.btn_clear.clicked.connect(self.clear_events)
        ctrl_layout.addWidget(self.btn_clear)

        self.btn_export_reg = QPushButton("Export to .REG")
        self.btn_export_reg.clicked.connect(self.export_reg)
        ctrl_layout.addWidget(self.btn_export_reg)

        self.btn_export_csv = QPushButton("Export to CSV")
        self.btn_export_csv.clicked.connect(self.export_csv)
        ctrl_layout.addWidget(self.btn_export_csv)

        layout.addLayout(ctrl_layout)

        # Stats
        self.lbl_stats = QLabel("Status: Idle | Changes: 0 | Changes/sec: 0")
        layout.addWidget(self.lbl_stats)

        # Table
        self.model = RegistryTableModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(False) # For performance, keeping it simple
        layout.addWidget(self.table)

        # Filter List
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Exclusion Filter (Path):"))
        self.txt_filter = QLineEdit()
        self.txt_filter.setPlaceholderText("e.g. HKEY_CURRENT_USER\\Software\\Microsoft")
        filter_layout.addWidget(self.txt_filter)
        layout.addLayout(filter_layout)

        # Timer for stats update
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats_display)
        self.stats_timer.start(1000)
        self.changes_last_sec = 0

    def init_worker(self):
        self.worker = ZMQSubscriberThread()
        self.worker.events_received.connect(self.on_events_received)
        self.worker.stats_updated.connect(self.on_stats_updated)

    def toggle_monitoring(self):
        if not self.monitoring:
            self.worker.start()
            self.btn_toggle.setText("Stop Monitoring")
            self.monitoring = True
            self.start_time = datetime.datetime.now()
        else:
            self.worker.stop()
            self.btn_toggle.setText("Start Monitoring")
            self.monitoring = False

    def on_events_received(self, events):
        # Apply local filtering if needed
        filter_text = self.txt_filter.text()
        if filter_text:
            filtered = [e for e in events if filter_text not in e.get("key_path", "")]
            self.filtered_count += len(events) - len(filtered)
            events = filtered
        
        if events:
            self.model.add_events(events)
            self.table.scrollToBottom()

    def on_stats_updated(self, count):
        self.total_changes += count
        self.changes_last_sec += count

    def update_stats_display(self):
        status = "Monitoring" if self.monitoring else "Idle"
        self.lbl_stats.setText(f"Status: {status} | Changes: {self.total_changes} | Changes/sec: {self.changes_last_sec} | Filtered: {self.filtered_count}")
        self.changes_last_sec = 0

    def clear_events(self):
        self.model.clear()
        self.total_changes = 0
        self.filtered_count = 0
        self.update_stats_display()

    def export_csv(self):
        if not self.model.events:
            QMessageBox.warning(self, "Export", "No events to export.")
            return
        
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if path:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.model.headers)
                writer.writeheader()
                for e in self.model.events:
                    # Map keys to headers
                    row = {
                        "Timestamp": e.get("timestamp"),
                        "Type": e.get("change_type"),
                        "Key Path": e.get("key_path"),
                        "Value Name": e.get("value_name"),
                        "Data Type": e.get("data_type"),
                        "Old Value": e.get("old_value"),
                        "New Value": e.get("new_value")
                    }
                    writer.writerow(row)
            QMessageBox.information(self, "Export", f"Exported {len(self.model.events)} events to CSV.")

    def format_reg_value(self, data_type, value):
        if data_type == "REG_DWORD":
            try:
                val = int(value)
                return f"dword:{val:08x}"
            except: return 'dword:00000000'
        elif data_type == "REG_QWORD":
            try:
                val = int(value)
                # QWORD is hex(b):XX,XX,XX,XX,XX,XX,XX,XX (little endian)
                b = val.to_bytes(8, byteorder='little')
                return "hex(b):" + ",".join(f"{x:02x}" for x in b)
            except: return 'hex(b):00,00,00,00,00,00,00,00'
        elif data_type == "REG_SZ":
            # Escape backslashes and quotes
            val = str(value).replace("\\", "\\\\").replace('"', '\\"')
            return f'"{val}"'
        else:
            return '"[Unsupported Type]"'

    def export_reg(self):
        if not self.model.events:
            QMessageBox.warning(self, "Export", "No events to export.")
            return
        
        path, _ = QFileDialog.getSaveFileName(self, "Save .REG", f"registry_changes_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.reg", "Registry Files (*.reg)")
        if not path:
            return

        # Group by type and path
        sections = {"NEW": {}, "MODIFIED": {}, "DELETED": {}}
        counts = {"NEW": 0, "MODIFIED": 0, "DELETED": 0}

        for e in self.model.events:
            ctype = e.get("change_type")
            key_path = e.get("key_path")
            val_name = e.get("value_name")
            dtype = e.get("data_type")
            new_val = e.get("new_value")
            old_val = e.get("old_value")

            if ctype not in sections: continue
            
            if key_path not in sections[ctype]:
                sections[ctype][key_path] = []
            
            sections[ctype][key_path].append({
                "name": val_name,
                "dtype": dtype,
                "value": new_val if ctype != "DELETED" else old_val,
                "old_value": old_val
            })
            counts[ctype] += 1

        try:
            with open(path, 'w', encoding='utf-16-le') as f:
                # UTF-16 LE BOM
                f.write('\ufeff')
                f.write("Windows Registry Editor Version 5.00\n\n")
                
                # Header
                f.write(";==================================================\n")
                f.write("; WINDOWS REGISTRY MONITOR - EXPORT REPORT\n")
                f.write(";==================================================\n")
                f.write(f"; Export Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                if self.start_time:
                    f.write(f"; Monitoring Period: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')} → {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(";\n")
                f.write("; Summary:\n")
                f.write(f";   NEW values: {counts['NEW']}\n")
                f.write(f";   MODIFIED values: {counts['MODIFIED']}\n")
                f.write(f";   DELETED values: {counts['DELETED']}\n")
                f.write(f";   TOTAL changes: {sum(counts.values())}\n")
                if self.txt_filter.text():
                    f.write(f"; Filters Applied: {self.txt_filter.text()}\n")
                f.write(";==================================================\n\n")

                # Section 1: NEW
                f.write(";==================================================\n")
                f.write(f"; SECTION 1: NEW VALUES ADDED (Total: {counts['NEW']})\n")
                f.write(";==================================================\n\n")
                for key, vals in sorted(sections["NEW"].items()):
                    f.write(f"[{key}]\n")
                    for v in vals:
                        reg_val = self.format_reg_value(v["dtype"], v["value"])
                        f.write(f'"{v["name"]}"={reg_val}\n')
                    f.write("\n")

                # Section 2: MODIFIED
                f.write(";==================================================\n")
                f.write(f"; SECTION 2: MODIFIED VALUES (Total: {counts['MODIFIED']})\n")
                f.write(";==================================================\n\n")
                for key, vals in sorted(sections["MODIFIED"].items()):
                    f.write(f"[{key}]\n")
                    for v in vals:
                        f.write(f'; Old value: {v["old_value"]}\n')
                        reg_val = self.format_reg_value(v["dtype"], v["value"])
                        f.write(f'"{v["name"]}"={reg_val}\n')
                    f.write("\n")

                # Section 3: DELETED
                f.write(";==================================================\n")
                f.write(f"; SECTION 3: DELETED VALUES (Total: {counts['DELETED']})\n")
                f.write(";==================================================\n\n")
                for key, vals in sorted(sections["DELETED"].items()):
                    f.write(f"[{key}]\n")
                    for v in vals:
                        f.write(f'; Original value was: {v["value"]}\n')
                        f.write(f'"{v["name"]}"=-\n')
                    f.write("\n")

            QMessageBox.information(self, "Export Complete!", 
                f"File: {path}\n\n"
                f"NEW values: {counts['NEW']}\n"
                f"MODIFIED values: {counts['MODIFIED']}\n"
                f"DELETED values: {counts['DELETED']}\n\n"
                "Important:\n"
                "- Review the file before applying\n"
                "- Deleted values are marked with (-) and need manual restoration")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export .reg file: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
