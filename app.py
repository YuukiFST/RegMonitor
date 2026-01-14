import sys
import json
import zmq
import datetime
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QTableView, QLabel, QLineEdit, QFileDialog, 
    QMessageBox, QHeaderView, QAbstractItemView, QTextEdit, QMenu,
    QListWidget, QGroupBox
)
from PyQt6.QtGui import QAction, QCloseEvent
from PyQt6.QtCore import Qt, QAbstractTableModel, QThread, pyqtSignal, QTimer

# Constants
ZMQ_ENDPOINT = "tcp://127.0.0.1:5555"
CONFIG_FILE = "config.json"

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
        if not index.isValid():
            return None
        
        event = self.events[index.row()]
        col = index.column()
        
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0: return event.get("timestamp")
            if col == 1: return event.get("change_type")
            if col == 2: return event.get("key_path")
            if col == 3: return event.get("value_name")
            if col == 4: return event.get("data_type")
            if col == 5: return str(event.get("old_value", ""))
            if col == 6: return str(event.get("new_value", ""))
        
        if role == Qt.ItemDataRole.ToolTipRole:
            if col == 2: return event.get("key_path")
            if col == 3: return event.get("value_name")
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
        self.load_config()
        self.init_worker()

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    config = json.load(f)
                    if "filtros_paths" in config:
                        paths = config.get("filtros_paths", [])
                    else:
                        filters_str = config.get("filters", "")
                        paths = [p.strip() for p in filters_str.split("\n") if p.strip()]
                    
                    self.list_filters.clear()
                    self.list_filters.addItems(paths)
            except Exception as e:
                print(f"Error loading config: {e}")

    def save_config(self):
        paths = []
        for i in range(self.list_filters.count()):
            paths.append(self.list_filters.item(i).text())
        
        config = {
            "filtros_paths": paths,
            "dwords_ignoradas": []
        }
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")

    def closeEvent(self, event: QCloseEvent):
        self.save_config()
        super().closeEvent(event)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # 1. Add Filter Section (Distinct place to add)
        add_filter_group = QGroupBox("Add Path to Filter")
        add_filter_layout = QHBoxLayout()
        self.ent_add_filter = QLineEdit()
        self.ent_add_filter.setPlaceholderText("Enter registry path to exclude (e.g., HKEY_LOCAL_MACHINE\\SOFTWARE\\...)")
        self.ent_add_filter.returnPressed.connect(self.add_current_path_to_filter)
        add_filter_layout.addWidget(self.ent_add_filter)
        
        self.btn_add_filter = QPushButton("Add Path")
        self.btn_add_filter.clicked.connect(self.add_current_path_to_filter)
        add_filter_layout.addWidget(self.btn_add_filter)
        add_filter_group.setLayout(add_filter_layout)
        layout.addWidget(add_filter_group)

        # 2. Main Row: Controls and Stats
        top_row = QHBoxLayout()
        
        ctrl_layout = QHBoxLayout()
        self.btn_toggle = QPushButton("Start Monitoring")
        self.btn_toggle.clicked.connect(self.toggle_monitoring)
        ctrl_layout.addWidget(self.btn_toggle)

        self.btn_clear = QPushButton("Clear Events")
        self.btn_clear.clicked.connect(self.clear_events)
        ctrl_layout.addWidget(self.btn_clear)

        self.btn_export_reg = QPushButton("Export to .REG")
        self.btn_export_reg.clicked.connect(self.export_reg)
        ctrl_layout.addWidget(self.btn_export_reg)
        top_row.addLayout(ctrl_layout, 2)

        self.lbl_stats = QLabel("Status: Idle | Changes: 0 | Filtered: 0")
        top_row.addWidget(self.lbl_stats, 1)
        layout.addLayout(top_row)

        # 3. View Filter Section (Distinct place to see)
        view_filter_group = QGroupBox("Excluded Paths (Filters)")
        view_filter_layout = QVBoxLayout()
        
        self.list_filters = QListWidget()
        self.list_filters.setToolTip("Select a path and press Delete or use the button below to remove it.")
        view_filter_layout.addWidget(self.list_filters)
        
        filter_btn_layout = QHBoxLayout()
        self.btn_remove_filter = QPushButton("Remove Selected Filter")
        self.btn_remove_filter.clicked.connect(self.remove_selected_filter)
        filter_btn_layout.addWidget(self.btn_remove_filter)
        
        self.btn_clear_filter = QPushButton("Clear All Filters")
        self.btn_clear_filter.clicked.connect(lambda: (self.list_filters.clear(), self.save_config()))
        filter_btn_layout.addWidget(self.btn_clear_filter)
        
        view_filter_layout.addLayout(filter_btn_layout)
        view_filter_group.setLayout(view_filter_layout)
        view_filter_group.setMaximumHeight(200) # Keep it compact
        layout.addWidget(view_filter_group)

        # 4. Table
        self.model = RegistryTableModel()
        self.table = QTableView()
        self.table.setModel(self.model)
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        layout.addWidget(self.table)

        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats_display)
        self.stats_timer.start(1000)
        self.changes_last_sec = 0

    def init_worker(self):
        self.worker = ZMQSubscriberThread()
        self.worker.events_received.connect(self.on_events_received)
        self.worker.stats_updated.connect(self.on_stats_updated)

    def remove_selected_filter(self):
        selected_items = self.list_filters.selectedItems()
        if not selected_items:
            return
        for item in selected_items:
            self.list_filters.takeItem(self.list_filters.row(item))
        self.save_config()

    def on_events_received(self, events):
        # Apply local filtering
        filters = []
        for i in range(self.list_filters.count()):
            filters.append(self.list_filters.item(i).text())

        if filters:
            filtered = []
            for e in events:
                key_path = e.get("key_path", "")
                if any(f in key_path for f in filters):
                    self.filtered_count += 1
                else:
                    filtered.append(e)
            events = filtered
        
        if events:
            self.model.add_events(events)
            self.table.scrollToBottom()

    def on_stats_updated(self, count):
        self.total_changes += count
        self.changes_last_sec += count

    def update_stats_display(self):
        status = "Monitoring" if self.monitoring else "Idle"
        self.lbl_stats.setText(f"Status: {status} | Changes: {self.total_changes} | Filtered: {self.filtered_count}")
        self.changes_last_sec = 0

    def show_context_menu(self, pos):
        index = self.table.indexAt(pos)
        if not index.isValid():
            return

        menu = QMenu(self)
        
        copy_path_action = QAction("Copy Path", self)
        copy_path_action.triggered.connect(lambda: self.copy_to_clipboard(index, 2))
        menu.addAction(copy_path_action)
        
        copy_val_action = QAction("Copy Value Name", self)
        copy_val_action.triggered.connect(lambda: self.copy_to_clipboard(index, 3))
        menu.addAction(copy_val_action)

        copy_row_action = QAction("Copy Full Row", self)
        copy_row_action.triggered.connect(lambda: self.copy_row_to_clipboard(index.row()))
        menu.addAction(copy_row_action)
        
        menu.addSeparator()

        exclude_action = QAction("Add to Exclude Filter", self)
        exclude_action.triggered.connect(lambda: self.add_to_exclude(index))
        menu.addAction(exclude_action)

        menu.exec(self.table.viewport().mapToGlobal(pos))

    def copy_to_clipboard(self, index, column=None):
        if column is not None:
            path_index = self.model.index(index.row(), column)
            text = self.model.data(path_index, Qt.ItemDataRole.DisplayRole)
        else:
            text = self.model.data(index, Qt.ItemDataRole.DisplayRole)
            
        if text:
            clipboard = QApplication.clipboard()
            clipboard.setText(str(text))

    def copy_row_to_clipboard(self, row):
        row_data = []
        for col in range(self.model.columnCount()):
            idx = self.model.index(row, col)
            val = self.model.data(idx, Qt.ItemDataRole.DisplayRole)
            row_data.append(str(val))
        
        text = "\t".join(row_data)
        clipboard = QApplication.clipboard()
        clipboard.setText(text)

    def add_to_exclude(self, index):
        path_index = self.model.index(index.row(), 2)
        path = self.model.data(path_index, Qt.ItemDataRole.DisplayRole)
        if path:
            existing_paths = []
            for i in range(self.list_filters.count()):
                existing_paths.append(self.list_filters.item(i).text())
            
            if path not in existing_paths:
                self.list_filters.addItem(path)
                self.save_config()

    def add_current_path_to_filter(self):
        path = self.ent_add_filter.text().strip()
        if path:
            existing_paths = []
            for i in range(self.list_filters.count()):
                existing_paths.append(self.list_filters.item(i).text())
                
            if path not in existing_paths:
                self.list_filters.addItem(path)
                self.ent_add_filter.clear()
                self.save_config()
            else:
                self.ent_add_filter.clear()

    def clear_events(self):
        self.model.clear()
        self.total_changes = 0
        self.filtered_count = 0
        self.update_stats_display()

    def format_reg_value(self, data_type, value):
        if data_type == "REG_DWORD":
            try:
                val = int(value)
                return f"dword:{val:08x}"
            except: return 'dword:00000000'
        elif data_type == "REG_QWORD":
            try:
                val = int(value)
                b = val.to_bytes(8, byteorder='little')
                return "hex(b):" + ",".join(f"{x:02x}" for x in b)
            except: return 'hex(b):00,00,00,00,00,00,00,00'
        elif data_type == "REG_SZ":
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
                f.write('\ufeff')
                f.write("Windows Registry Editor Version 5.00\n\n")
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
                
                # Use list_filters for the report
                if self.list_filters.count() > 0:
                    f.write(f"; Filters Applied:\n")
                    for i in range(self.list_filters.count()):
                        f.write(f";   - {self.list_filters.item(i).text()}\n")
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
