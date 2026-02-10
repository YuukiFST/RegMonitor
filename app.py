import sys
import json
import zmq
import datetime
import os
import logging
import subprocess
import ctypes
from typing import Optional, Any
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QTableView, QLabel, QLineEdit, QFileDialog, 
    QMessageBox, QHeaderView, QAbstractItemView, QMenu,
    QListWidget, QGroupBox, QListWidgetItem
)
from PyQt6.QtGui import QAction, QCloseEvent, QKeyEvent, QIcon
from PyQt6.QtCore import Qt, QAbstractTableModel, QThread, pyqtSignal, QTimer, QEvent, QModelIndex

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


ZMQ_ENDPOINT = "tcp://127.0.0.1:5555"
CONFIG_FILE = "config.json"
AUTOCOMPLETE_DEBOUNCE_MS = 300
AUTOCOMPLETE_MAX_SUGGESTIONS = 5
MAX_EVENTS = 5000
BACKEND_EXE = "main.exe"
DEFAULT_OPACITY = 0.9
MIN_OPACITY = 0.1
MAX_OPACITY = 1.0


SCORE_WEIGHT_LCP = 10
SCORE_WEIGHT_EXACT_MATCH = 1000
SCORE_WEIGHT_PREFIX_MATCH = 500
SCORE_WEIGHT_PARENT_MATCH = 250


COL_TIMESTAMP = 0
COL_CHANGE_TYPE = 1
COL_KEY_PATH = 2
COL_VALUE_NAME = 3
COL_DATA_TYPE = 4
COL_OLD_VALUE = 5
COL_NEW_VALUE = 6


DEFAULT_WINDOW_WIDTH = 1200
DEFAULT_WINDOW_HEIGHT = 800
STATS_UPDATE_INTERVAL_MS = 1000
AUTO_SCROLL_THRESHOLD = 5
FOCUS_OUT_DELAY_MS = 100


DWMWA_USE_IMMERSIVE_DARK_MODE_NEW = 20
DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19
DWMWA_CAPTION_COLOR = 35
DWMWA_TEXT_COLOR = 36


CHANGE_TYPE_NEW = "NEW"
CHANGE_TYPE_MODIFIED = "MODIFIED"
CHANGE_TYPE_DELETED = "DELETED"

DARK_STYLESHEET = """
* {
    font-family: 'Iosevka', 'Consolas', 'Courier New', monospace;
    font-size: 13px;
}

QMainWindow, QWidget {
    background-color: #000000;
    color: #e0e0e0;
}

QGroupBox {
    background-color: #0a0a0a;
    border: 1px solid #1a1a1a;
    border-radius: 6px;
    margin-top: 30px;
    padding: 8px 12px 12px 12px;
    font-weight: bold;
    color: #b0b0b0;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 6px 14px;
    margin-left: 6px;
    margin-bottom: 8px;
    color: #c8c8c8;
}

QPushButton {
    background-color: #1a1a1a;
    color: #e0e0e0;
    border: 1px solid #2a2a2a;
    border-radius: 4px;
    padding: 6px 16px;
    min-height: 22px;
}

QPushButton:hover {
    background-color: #252525;
    border-color: #0078d4;
}

QPushButton:pressed {
    background-color: #0078d4;
    color: #ffffff;
}

QLineEdit {
    background-color: #0d0d0d;
    color: #e0e0e0;
    border: 1px solid #1a1a1a;
    border-radius: 4px;
    padding: 6px 8px;
    selection-background-color: #0078d4;
}

QLineEdit:focus {
    border-color: #0078d4;
}

QListWidget {
    background-color: #0a0a0a;
    color: #e0e0e0;
    border: 1px solid #1a1a1a;
    border-radius: 4px;
    outline: none;
}

QListWidget::item {
    padding: 4px 8px;
    border-bottom: 1px solid #111111;
}

QListWidget::item:selected {
    background-color: #0078d4;
    color: #ffffff;
}

QListWidget::item:hover {
    background-color: #151515;
}

QTableView {
    background-color: #000000;
    alternate-background-color: #0a0a0a;
    color: #d0d0d0;
    border: 1px solid #1a1a1a;
    border-radius: 4px;
    gridline-color: transparent;
    selection-background-color: #0078d4;
    selection-color: #ffffff;
    outline: none;
}

QTableView::item {
    padding: 4px 6px;
    border: none;
}

QTableView::item:hover {
    background-color: #151515;
}

QHeaderView::section {
    background-color: #0d0d0d;
    color: #a0a0a0;
    border: none;
    border-bottom: 2px solid #1a1a1a;
    border-right: 1px solid #111111;
    padding: 6px 8px;
    font-weight: bold;
}

QScrollBar:vertical {
    background-color: #000000;
    width: 8px;
    border: none;
}

QScrollBar::handle:vertical {
    background-color: #2a2a2a;
    border-radius: 4px;
    min-height: 30px;
}

QScrollBar::handle:vertical:hover {
    background-color: #3a3a3a;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    background-color: #000000;
    height: 8px;
    border: none;
}

QScrollBar::handle:horizontal {
    background-color: #2a2a2a;
    border-radius: 4px;
    min-width: 30px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #3a3a3a;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}

QLabel {
    color: #b0b0b0;
}

QMenu {
    background-color: #0d0d0d;
    color: #e0e0e0;
    border: 1px solid #1a1a1a;
    border-radius: 4px;
    padding: 4px;
}

QMenu::item {
    padding: 6px 24px;
    border-radius: 3px;
}

QMenu::item:selected {
    background-color: #0078d4;
    color: #ffffff;
}

QMenu::separator {
    height: 1px;
    background-color: #1a1a1a;
    margin: 4px 8px;
}

QMessageBox {
    background-color: #0d0d0d;
    color: #e0e0e0;
}

QToolTip {
    background-color: #1a1a1a;
    color: #e0e0e0;
    border: 1px solid #2a2a2a;
    border-radius: 3px;
    padding: 4px 8px;
}
"""


def get_lcp_length(s1: str, s2: str) -> int:
    s1_lower = s1.lower()
    s2_lower = s2.lower()
    min_len = min(len(s1_lower), len(s2_lower))
    lcp = 0
    for i in range(min_len):
        if s1_lower[i] == s2_lower[i]:
            lcp += 1
        else:
            break
    return lcp


def normalize_path(path: str) -> str:
    return path.strip().rstrip("\\").lower()


def is_child_of(child_path: str, parent_path: str) -> bool:
    child_norm = normalize_path(child_path)
    parent_norm = normalize_path(parent_path)
    return child_norm.startswith(parent_norm + "\\")


def check_if_child_of_existing(new_path: str, existing_paths: list[str]) -> tuple[bool, Optional[str]]:
    new_norm = normalize_path(new_path)
    for existing in existing_paths:
        existing_norm = normalize_path(existing)
        if new_norm.startswith(existing_norm + "\\"):
            return True, existing
    return False, None


def find_children_of(parent_path: str, existing_paths: list[str]) -> list[str]:
    parent_norm = normalize_path(parent_path)
    children = []
    for existing in existing_paths:
        existing_norm = normalize_path(existing)
        if existing_norm.startswith(parent_norm + "\\"):
            children.append(existing)
    return children


def is_exact_duplicate(new_path: str, existing_paths: list[str]) -> bool:
    new_norm = normalize_path(new_path)
    for existing in existing_paths:
        if normalize_path(existing) == new_norm:
            return True
    return False


def get_path_suggestions(user_input: str, existing_paths: list[str], max_results: int = 5) -> list[str]:
    """Return paths that strictly match the user input as a prefix.
    
    Only returns paths where:
    - The user input is a prefix of the path (user is typing toward a known path)
    - The path is a prefix of the user input (user typed past a known parent)
    - Exact match
    """
    if not user_input or not user_input.strip():
        return []
    
    user_input = user_input.strip()
    user_lower = user_input.lower()
    
    scored_paths = []
    for path in existing_paths:
        if not path:
            continue
        
        path_lower = path.lower()
        
        is_exact = user_lower == path_lower
        user_is_prefix_of_path = path_lower.startswith(user_lower)
        path_is_prefix_of_user = user_lower.startswith(path_lower)
        
        if not (is_exact or user_is_prefix_of_path or path_is_prefix_of_user):
            continue
        
        lcp = get_lcp_length(user_input, path)
        
        score = (
            lcp * SCORE_WEIGHT_LCP +
            (SCORE_WEIGHT_EXACT_MATCH if is_exact else 0) +
            (SCORE_WEIGHT_PREFIX_MATCH if user_is_prefix_of_path else 0) +
            (SCORE_WEIGHT_PARENT_MATCH if path_is_prefix_of_user else 0)
        )
        
        scored_paths.append((score, lcp, path))
    
    scored_paths.sort(key=lambda x: (-x[0], -x[1]))
    
    return [path for _, _, path in scored_paths[:max_results]]


class AutocompleteLineEdit(QLineEdit):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.main_window: Optional["MainWindow"] = None
        self.suggestion_list: Optional[QListWidget] = None
        self.debounce_timer = QTimer()
        self.debounce_timer.setSingleShot(True)
        self.debounce_timer.timeout.connect(self._do_autocomplete)
        
        self.textChanged.connect(self._on_text_changed)
    
    def set_main_window(self, main_window: "MainWindow") -> None:
        self.main_window = main_window
        
        self.suggestion_list = QListWidget(main_window)
        self.suggestion_list.setWindowFlags(Qt.WindowType.ToolTip)
        self.suggestion_list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.suggestion_list.setMaximumHeight(150)
        self.suggestion_list.setStyleSheet("""
            QListWidget {
                background-color: #2b2b2b;
                color: #e0e0e0;
                border: 1px solid #555;
                font-family: Consolas, monospace;
                font-size: 12px;
            }
            QListWidget::item {
                padding: 4px 8px;
            }
            QListWidget::item:hover {
                background-color: #3a3a3a;
            }
            QListWidget::item:selected {
                background-color: #0078d4;
                color: white;
            }
        """)
        self.suggestion_list.itemClicked.connect(self._on_suggestion_clicked)
        self.suggestion_list.hide()
    
    def _on_text_changed(self, text: str) -> None:
        self.debounce_timer.stop()
        if text.strip():
            self.debounce_timer.start(AUTOCOMPLETE_DEBOUNCE_MS)
        else:
            self._hide_suggestions()
    
    def _do_autocomplete(self) -> None:
        if not self.main_window or not self.suggestion_list:
            return
        
        user_input = self.text().strip()
        if not user_input:
            self._hide_suggestions()
            return
        
        existing_paths = self.main_window._get_filter_paths()
        
        suggestions = get_path_suggestions(user_input, existing_paths, AUTOCOMPLETE_MAX_SUGGESTIONS)
        
        if not suggestions:
            self._hide_suggestions()
            return
        
        self.suggestion_list.clear()
        user_lower = user_input.lower()
        
        for path in suggestions:
            item = QListWidgetItem()
            
            if path.lower() == user_lower:
                item.setText(f"[Exact] {path}")
            elif path.lower().startswith(user_lower):
                item.setText(f"[Prefix] {path}")
            elif user_lower.startswith(path.lower()):
                item.setText(f"[Parent] {path}")
            else:
                item.setText(path)
            
            item.setData(Qt.ItemDataRole.UserRole, path)
            self.suggestion_list.addItem(item)
        
        self._show_suggestions()
    
    def _show_suggestions(self) -> None:
        if not self.suggestion_list or self.suggestion_list.count() == 0:
            return
        
        global_pos = self.mapToGlobal(self.rect().bottomLeft())
        self.suggestion_list.move(global_pos)
        self.suggestion_list.setFixedWidth(self.width())
        self.suggestion_list.show()
        self.suggestion_list.raise_()
    
    def _hide_suggestions(self) -> None:
        if self.suggestion_list:
            self.suggestion_list.hide()
    
    def _on_suggestion_clicked(self, item: QListWidgetItem) -> None:
        path = item.data(Qt.ItemDataRole.UserRole)
        if path:
            self.setText(path)
        self._hide_suggestions()
        self.setFocus()
    
    def keyPressEvent(self, event: QKeyEvent) -> None:
        if not self.suggestion_list or not self.suggestion_list.isVisible():
            super().keyPressEvent(event)
            return
        
        if event.key() == Qt.Key.Key_Down:
            current = self.suggestion_list.currentRow()
            if current < self.suggestion_list.count() - 1:
                self.suggestion_list.setCurrentRow(current + 1)
            elif current == -1 and self.suggestion_list.count() > 0:
                self.suggestion_list.setCurrentRow(0)
            return
        
        elif event.key() == Qt.Key.Key_Up:
            current = self.suggestion_list.currentRow()
            if current > 0:
                self.suggestion_list.setCurrentRow(current - 1)
            return
        
        elif event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            current_item = self.suggestion_list.currentItem()
            if current_item:
                path = current_item.data(Qt.ItemDataRole.UserRole)
                if path:
                    self.setText(path)
                self._hide_suggestions()
                return
            else:
                self._hide_suggestions()
                super().keyPressEvent(event)
                return
        
        elif event.key() == Qt.Key.Key_Escape:
            self._hide_suggestions()
            return
        
        elif event.key() == Qt.Key.Key_Tab:
            current_item = self.suggestion_list.currentItem()
            if current_item:
                path = current_item.data(Qt.ItemDataRole.UserRole)
                if path:
                    self.setText(path)
                self._hide_suggestions()
            return
        
        super().keyPressEvent(event)
    
    def focusOutEvent(self, event: QEvent) -> None:
        QTimer.singleShot(FOCUS_OUT_DELAY_MS, self._hide_suggestions)
        super().focusOutEvent(event)

class RegistryTableModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self.headers: list[str] = ["Timestamp", "Type", "Key Path", "Value Name", "Data Type", "Old Value", "New Value"]
        self.events: list[dict[str, Any]] = []

    def rowCount(self, parent: Optional[QModelIndex] = None) -> int:
        return len(self.events)

    def columnCount(self, parent: Optional[QModelIndex] = None) -> int:
        return len(self.headers)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        
        event = self.events[index.row()]
        col = index.column()
        
        if role == Qt.ItemDataRole.DisplayRole:
            if col == COL_TIMESTAMP: return event.get("timestamp")
            if col == COL_CHANGE_TYPE: return event.get("change_type")
            if col == COL_KEY_PATH: return event.get("key_path")
            if col == COL_VALUE_NAME: return event.get("value_name")
            if col == COL_DATA_TYPE: return event.get("data_type")
            if col == COL_OLD_VALUE: return str(event.get("old_value", ""))
            if col == COL_NEW_VALUE: return str(event.get("new_value", ""))
        
        if role == Qt.ItemDataRole.ToolTipRole:
            if col == COL_KEY_PATH: return event.get("key_path")
            if col == COL_VALUE_NAME: return event.get("value_name")
            if col == COL_OLD_VALUE: return str(event.get("old_value", ""))
            if col == COL_NEW_VALUE: return str(event.get("new_value", ""))
            
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.headers[section]
        return None

    def add_events(self, new_events: list[dict[str, Any]]) -> None:
        total_after = len(self.events) + len(new_events)
        if total_after > MAX_EVENTS:
            
            self.beginResetModel()
            self.events.extend(new_events)
            overflow = len(self.events) - MAX_EVENTS
            if overflow > 0:
                self.events = self.events[overflow:]
            self.endResetModel()
        else:
            self.beginInsertRows(QModelIndex(), len(self.events), len(self.events) + len(new_events) - 1)
            self.events.extend(new_events)
            self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self.events = []
        self.endResetModel()

    def remove_events_matching_filter(self, filter_path: str) -> int:
        filter_norm = normalize_path(filter_path)
        indices_to_remove = []
        for i, event in enumerate(self.events):
            key_path = event.get("key_path", "")
            key_norm = normalize_path(key_path)
            if key_norm == filter_norm or key_norm.startswith(filter_norm + "\\"):
                indices_to_remove.append(i)
        
        if not indices_to_remove:
            return 0
        
        self.beginResetModel()
        for i in reversed(indices_to_remove):
            del self.events[i]
        self.endResetModel()
        
        return len(indices_to_remove)

class ZMQSubscriberThread(QThread):
    events_received = pyqtSignal(list)
    stats_updated = pyqtSignal(int)

    def __init__(self) -> None:
        super().__init__()
        self.running: bool = False
        self.context: zmq.Context = zmq.Context()
        self.subscriber: zmq.Socket = self.context.socket(zmq.SUB)
        self.subscriber.setsockopt(zmq.LINGER, 0)

    def run(self) -> None:
        self.subscriber.connect(ZMQ_ENDPOINT)
        self.subscriber.setsockopt_string(zmq.SUBSCRIBE, "")
        self.running = True
        
        while self.running:
            try:
                if self.subscriber.poll(100):
                    message = self.subscriber.recv_json()
                    events = message.get("events", [])
                    if events:
                        self.events_received.emit(events)
                        self.stats_updated.emit(len(events))
            except zmq.ZMQError as e:
                if self.running:
                    logger.error(f"ZMQ Error: {e}")
                    self.msleep(100)
            except Exception as e:
                if self.running:
                    logger.error(f"Error: {e}")
                    self.msleep(100)

    def stop(self) -> None:
        self.running = False
        self.wait(2000)
        try:
            self.subscriber.close()
            self.context.term()
        except Exception:
            pass

class BackendProcessManager:
    def __init__(self, executable_path: str) -> None:
        self.executable_path = executable_path
        self.process: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        """Starts the backend process if not already running."""
        if self.is_running():
            logger.info("Backend is already running.")
            return True

        if not os.path.exists(self.executable_path):
            
            base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
            full_path = os.path.join(base_path, self.executable_path)
            if not os.path.exists(full_path):
                logger.error(f"Backend executable not found at {self.executable_path} or {full_path}")
                return False
            self.executable_path = full_path

        try:
            logger.info(f"Starting backend: {self.executable_path}")
            self.process = subprocess.Popen(
                [self.executable_path],
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            return True
        except Exception as e:
            logger.error(f"Failed to start backend: {e}")
            return False

    def stop(self) -> None:
        """Stops the backend process."""
        if self.process:
            logger.info("Stopping backend...")
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                logger.warning("Backend did not exit cleanly, killing...")
                self.process.kill()
            self.process = None

    def is_running(self) -> bool:
        """Simple check if we have a process handle and it's active."""
        if self.process is None:
            return False
        return self.process.poll() is None

class MainWindow(QMainWindow):
    UNDO_STACK_MAX_SIZE = 20

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Windows Registry Monitor")
        self.resize(DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT)

        
        icon_path = os.path.join(
            getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__))),
            'registry.ico'
        )
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        self.setWindowOpacity(DEFAULT_OPACITY)

        self.total_changes: int = 0
        self.filtered_count: int = 0
        self.start_time: Optional[datetime.datetime] = None
        self.monitoring: bool = False
        self._filter_undo_stack: list[list[str]] = []

        self.init_ui()
        self.load_config()
        self.init_worker()
        self.backend_manager = BackendProcessManager(BACKEND_EXE)
        self.start_backend()
        self.ent_add_filter.set_main_window(self)

        
        self._apply_dark_title_bar()

    def _apply_dark_title_bar(self) -> None:
        """Use DWM API to set a black title bar matching the window background."""
        try:
            hwnd = int(self.winId())
            
            dark_value = ctypes.c_int(1)
            result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_NEW,
                ctypes.byref(dark_value), ctypes.sizeof(dark_value)
            )
            if result != 0:
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD,
                    ctypes.byref(dark_value), ctypes.sizeof(dark_value)
                )
            
            black_color = ctypes.c_uint(0x00000000)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_CAPTION_COLOR,
                ctypes.byref(black_color), ctypes.sizeof(black_color)
            )
            
            text_color = ctypes.c_uint(0x00E0E0E0)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_TEXT_COLOR,
                ctypes.byref(text_color), ctypes.sizeof(text_color)
            )
        except Exception as e:
            logger.warning(f"Could not apply dark title bar: {e}")

    def start_backend(self) -> None:
        if not self.backend_manager.start():
            QMessageBox.critical(self, "Backend Error", "Could not start the registry monitoring backend (main.exe). Please ensure it exists and you have administrator privileges.")

    def load_config(self) -> None:
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    config = json.load(f)
                    if "excluded_paths" in config:
                        paths = config.get("excluded_paths", [])
                    elif "filtros_paths" in config:
                        paths = config.get("filtros_paths", [])
                    else:
                        filters_str = config.get("filters", "")
                        paths = [p.strip() for p in filters_str.split("\n") if p.strip()]
                    
                    self.list_filters.clear()
                    self.list_filters.addItems(paths)

                    opacity = config.get("opacity", DEFAULT_OPACITY)
                    clamped_opacity = max(MIN_OPACITY, min(MAX_OPACITY, float(opacity)))
                    self.setWindowOpacity(clamped_opacity)
            except Exception as e:
                logger.error(f"Error loading config: {e}")

    def _get_filter_paths(self) -> list[str]:
        """Return all paths currently in the filter list."""
        return [self.list_filters.item(i).text() for i in range(self.list_filters.count())]

    def save_config(self) -> None:
        paths = self._get_filter_paths()
        
        config = {
            "opacity": self.windowOpacity(),
            "excluded_paths": paths,
            "ignored_dwords": []
        }
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving config: {e}")

    def closeEvent(self, event: QCloseEvent) -> None:
        self.save_config()
        if self.monitoring:
            self.worker.stop()
        if hasattr(self, 'backend_manager'):
            self.backend_manager.stop()
        if hasattr(self, 'ent_add_filter') and self.ent_add_filter.suggestion_list:
            self.ent_add_filter.suggestion_list.close()
        super().closeEvent(event)

    def init_ui(self) -> None:
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        
        add_filter_group = QGroupBox("Add Path to Filter")
        add_filter_layout = QHBoxLayout()
        self.ent_add_filter = AutocompleteLineEdit()
        self.ent_add_filter.setPlaceholderText("Enter registry path to exclude (e.g., HKEY_LOCAL_MACHINE\\SOFTWARE\\...)")
        self.ent_add_filter.returnPressed.connect(self.add_current_path_to_filter)
        self.ent_add_filter.textChanged.connect(self._filter_excluded_paths_list)
        add_filter_layout.addWidget(self.ent_add_filter)
        
        self.btn_add_filter = QPushButton("Add Path")
        self.btn_add_filter.clicked.connect(self.add_current_path_to_filter)
        add_filter_layout.addWidget(self.btn_add_filter)
        add_filter_group.setLayout(add_filter_layout)
        layout.addWidget(add_filter_group)

        layout.addSpacing(8)

        
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

        self.lbl_stats = QLabel()
        self.lbl_stats.setTextFormat(Qt.TextFormat.RichText)
        top_row.addWidget(self.lbl_stats, 1)
        layout.addLayout(top_row)

        layout.addSpacing(8)

        
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
        self.btn_clear_filter.clicked.connect(self.clear_all_filters)
        filter_btn_layout.addWidget(self.btn_clear_filter)

        self.btn_undo_filter = QPushButton("Undo")
        self.btn_undo_filter.clicked.connect(self.undo_filter_action)
        self.btn_undo_filter.setEnabled(False)
        filter_btn_layout.addWidget(self.btn_undo_filter)
        
        view_filter_layout.addLayout(filter_btn_layout)
        view_filter_group.setLayout(view_filter_layout)
        view_filter_group.setMinimumHeight(250)
        view_filter_group.setMaximumHeight(350)
        layout.addWidget(view_filter_group)

        layout.addSpacing(8)

        
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
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        
        layout.addWidget(self.table)

        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats_display)
        self.stats_timer.start(STATS_UPDATE_INTERVAL_MS)
        self.changes_last_sec = 0

    def init_worker(self) -> None:
        self.worker = ZMQSubscriberThread()
        self.worker.events_received.connect(self.on_events_received)
        self.worker.stats_updated.connect(self.on_stats_updated)

    def toggle_monitoring(self) -> None:
        if not self.monitoring:
            self.monitoring = True
            self.start_time = datetime.datetime.now()
            self.init_worker()
            self.worker.start()
            self.btn_toggle.setText("Stop Monitoring")
        else:
            self.monitoring = False
            self.worker.stop()
            self.btn_toggle.setText("Start Monitoring")
        self.update_stats_display()

    def _push_filter_undo_state(self) -> None:
        """Snapshot current filter list onto the undo stack."""
        current_paths = self._get_filter_paths()
        self._filter_undo_stack.append(current_paths)
        if len(self._filter_undo_stack) > self.UNDO_STACK_MAX_SIZE:
            self._filter_undo_stack.pop(0)
        self.btn_undo_filter.setEnabled(True)

    def undo_filter_action(self) -> None:
        """Restore the previous filter list state."""
        if not self._filter_undo_stack:
            return
        previous_paths = self._filter_undo_stack.pop()
        self.list_filters.clear()
        self.list_filters.addItems(previous_paths)
        self.save_config()
        self.btn_undo_filter.setEnabled(len(self._filter_undo_stack) > 0)

    def clear_all_filters(self) -> None:
        """Clear all filters with confirmation dialog."""
        if self.list_filters.count() == 0:
            return
        reply = QMessageBox.warning(
            self,
            "Clear All Filters",
            f"Are you sure you want to remove all {self.list_filters.count()} excluded paths?\n\n"
            "You can undo this action with the Undo button.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._push_filter_undo_state()
            self.list_filters.clear()
            self.save_config()

    def remove_selected_filter(self) -> None:
        selected_items = self.list_filters.selectedItems()
        if not selected_items:
            return
        self._push_filter_undo_state()
        for item in selected_items:
            self.list_filters.takeItem(self.list_filters.row(item))
        self.save_config()

    def _filter_excluded_paths_list(self, search_text: str) -> None:
        """Show/hide items in the excluded paths list based on the typed text."""
        search_lower = search_text.strip().lower()
        for i in range(self.list_filters.count()):
            item = self.list_filters.item(i)
            if not search_lower:
                item.setHidden(False)
            else:
                path_lower = item.text().lower()
                matches = (
                    search_lower in path_lower or
                    path_lower.startswith(search_lower) or
                    search_lower.startswith(path_lower)
                )
                item.setHidden(not matches)

    def on_events_received(self, events: list[dict[str, Any]]) -> None:
        
        filter_set = set()
        for path in self._get_filter_paths():
            filter_set.add(normalize_path(path))

        if filter_set:
            filtered = []
            for e in events:
                key_path = e.get("key_path", "")
                key_norm = normalize_path(key_path)
                should_filter = False
                for f in filter_set:
                    if key_norm == f or key_norm.startswith(f + "\\"):
                        should_filter = True
                        break
                if should_filter:
                    self.filtered_count += 1
                else:
                    filtered.append(e)
            events = filtered
        
        if events:
            
            scrollbar = self.table.verticalScrollBar()
            at_bottom = scrollbar.value() >= scrollbar.maximum() - AUTO_SCROLL_THRESHOLD
            self.model.add_events(events)
            if at_bottom:
                self.table.scrollToBottom()

    def on_stats_updated(self, count: int) -> None:
        self.total_changes += count
        self.changes_last_sec += count

    def update_stats_display(self) -> None:
        if self.monitoring:
            status_html = '<span style="color: #00cc66; font-weight: bold;">Monitoring</span>'
        else:
            status_html = '<span style="color: #ff4444; font-weight: bold;">Idle</span>'
        self.lbl_stats.setText(
            f'Status: {status_html} | Changes: {self.total_changes} | Filtered: {self.filtered_count}'
        )
        self.changes_last_sec = 0

    def show_context_menu(self, pos) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return

        menu = QMenu(self)
        
        copy_path_action = QAction("Copy Path", self)
        copy_path_action.triggered.connect(lambda: self.copy_to_clipboard(index, COL_KEY_PATH))
        menu.addAction(copy_path_action)
        
        copy_val_action = QAction("Copy Value Name", self)
        copy_val_action.triggered.connect(lambda: self.copy_to_clipboard(index, COL_VALUE_NAME))
        menu.addAction(copy_val_action)

        copy_row_action = QAction("Copy Full Row", self)
        copy_row_action.triggered.connect(lambda: self.copy_row_to_clipboard(index.row()))
        menu.addAction(copy_row_action)
        
        menu.addSeparator()

        exclude_action = QAction("Add to Exclude Filter", self)
        exclude_action.triggered.connect(lambda: self.add_to_exclude(index))
        menu.addAction(exclude_action)

        menu.exec(self.table.viewport().mapToGlobal(pos))

    def copy_to_clipboard(self, index: QModelIndex, column: Optional[int] = None) -> None:
        if column is not None:
            path_index = self.model.index(index.row(), column)
            text = self.model.data(path_index, Qt.ItemDataRole.DisplayRole)
        else:
            text = self.model.data(index, Qt.ItemDataRole.DisplayRole)
            
        if text:
            clipboard = QApplication.clipboard()
            clipboard.setText(str(text))

    def copy_row_to_clipboard(self, row: int) -> None:
        row_data = []
        for col in range(self.model.columnCount()):
            idx = self.model.index(row, col)
            val = self.model.data(idx, Qt.ItemDataRole.DisplayRole)
            row_data.append(str(val))
        
        text = "\t".join(row_data)
        clipboard = QApplication.clipboard()
        clipboard.setText(text)

    def add_to_exclude(self, index: QModelIndex) -> None:
        path_index = self.model.index(index.row(), COL_KEY_PATH)
        path = self.model.data(path_index, Qt.ItemDataRole.DisplayRole)
        if path:
            self.add_path_with_validation(path)

    def show_parent_exists_warning(self, child_path: str, parent_path: str) -> None:
        QMessageBox.warning(
            self,
            "Path Already Covered",
            f"Cannot add:\n{child_path}\n\n"
            f"Already covered by:\n{parent_path}\n\n"
            "The parent path already monitors all subkeys."
        )

    def show_children_removed_info(self, removed_paths: list[str]) -> None:
        if len(removed_paths) <= 10:
            paths_text = "\n".join(f"• {p}" for p in removed_paths)
        else:
            paths_text = "\n".join(f"• {p}" for p in removed_paths[:10])
            paths_text += f"\n... and {len(removed_paths) - 10} more"
        
        QMessageBox.information(
            self,
            "Redundant Paths Removed",
            f"Removed {len(removed_paths)} child path(s):\n\n{paths_text}\n\n"
            "The new parent path covers these automatically."
        )

    def add_path_with_validation(self, path: str) -> bool:
        path = path.strip()
        if not path:
            return False
        
        existing_paths = self._get_filter_paths()
        
        if is_exact_duplicate(path, existing_paths):
            QMessageBox.warning(self, "Duplicate Path", f"This path already exists in the filter list:\n{path}")
            return False
        
        is_child, parent_path = check_if_child_of_existing(path, existing_paths)
        if is_child:
            self.show_parent_exists_warning(path, parent_path)
            return False
        
        children_to_remove = find_children_of(path, existing_paths)
        
        if children_to_remove:
            for child in children_to_remove:
                items = self.list_filters.findItems(child, Qt.MatchFlag.MatchExactly)
                for item in items:
                    self.list_filters.takeItem(self.list_filters.row(item))
        
        self.list_filters.addItem(path)
        self.save_config()
        
        removed_count = self.model.remove_events_matching_filter(path)
        if removed_count > 0:
            self.filtered_count += removed_count
            self.update_stats_display()
        
        if children_to_remove:
            self.show_children_removed_info(children_to_remove)
        
        return True

    def add_current_path_to_filter(self) -> None:
        path = self.ent_add_filter.text().strip()
        if path:
            self.add_path_with_validation(path)
            self.ent_add_filter.clear()

    def clear_events(self) -> None:
        self.model.clear()
        self.total_changes = 0
        self.filtered_count = 0
        self.update_stats_display()

    def format_reg_value(self, data_type: str, value: Any) -> str:
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

    def export_reg(self) -> None:
        if not self.model.events:
            QMessageBox.warning(self, "Export", "No events to export.")
            return
        
        path, _ = QFileDialog.getSaveFileName(self, "Save .REG", f"registry_changes_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.reg", "Registry Files (*.reg)")
        if not path:
            return

        sections = {CHANGE_TYPE_NEW: {}, CHANGE_TYPE_MODIFIED: {}, CHANGE_TYPE_DELETED: {}}
        counts = {CHANGE_TYPE_NEW: 0, CHANGE_TYPE_MODIFIED: 0, CHANGE_TYPE_DELETED: 0}

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
                "value": new_val if ctype != CHANGE_TYPE_DELETED else old_val,
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
                f.write(f";   NEW values: {counts[CHANGE_TYPE_NEW]}\n")
                f.write(f";   MODIFIED values: {counts[CHANGE_TYPE_MODIFIED]}\n")
                f.write(f";   DELETED values: {counts[CHANGE_TYPE_DELETED]}\n")
                f.write(f";   TOTAL changes: {sum(counts.values())}\n")
                
                filter_paths = self._get_filter_paths()
                if filter_paths:
                    f.write("; Filters Applied:\n")
                    for filter_path in filter_paths:
                        f.write(f";   - {filter_path}\n")
                f.write(";==================================================\n\n")


                
                f.write(";==================================================\n")
                f.write(f"; SECTION 1: NEW VALUES ADDED (Total: {counts[CHANGE_TYPE_NEW]})\n")
                f.write(";==================================================\n\n")
                for key, vals in sorted(sections[CHANGE_TYPE_NEW].items()):
                    f.write(f"[{key}]\n")
                    for v in vals:
                        reg_val = self.format_reg_value(v["dtype"], v["value"])
                        f.write(f'"{v["name"]}"={reg_val}\n')
                    f.write("\n")

                
                f.write(";==================================================\n")
                f.write(f"; SECTION 2: MODIFIED VALUES (Total: {counts[CHANGE_TYPE_MODIFIED]})\n")
                f.write(";==================================================\n\n")
                for key, vals in sorted(sections[CHANGE_TYPE_MODIFIED].items()):
                    f.write(f"[{key}]\n")
                    for v in vals:
                        f.write(f'; Old value: {v["old_value"]}\n')
                        reg_val = self.format_reg_value(v["dtype"], v["value"])
                        f.write(f'"{v["name"]}"={reg_val}\n')
                    f.write("\n")

                
                f.write(";==================================================\n")
                f.write(f"; SECTION 3: DELETED VALUES (Total: {counts[CHANGE_TYPE_DELETED]})\n")
                f.write(";==================================================\n\n")
                for key, vals in sorted(sections[CHANGE_TYPE_DELETED].items()):
                    f.write(f"[{key}]\n")
                    for v in vals:
                        f.write(f'; Original value was: {v["value"]}\n')
                        f.write(f'"{v["name"]}"=-\n')
                    f.write("\n")

            QMessageBox.information(self, "Export Complete!", 
                f"File: {path}\n\n"
                f"NEW values: {counts[CHANGE_TYPE_NEW]}\n"
                f"MODIFIED values: {counts[CHANGE_TYPE_MODIFIED]}\n"
                f"DELETED values: {counts[CHANGE_TYPE_DELETED]}\n\n"
                "Important:\n"
                "- Review the file before applying\n"
                "- Deleted values are marked with (-) and need manual restoration")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export .reg file: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_STYLESHEET)
    window = MainWindow()
    window.show()
    
    window._apply_dark_title_bar()
    sys.exit(app.exec())
