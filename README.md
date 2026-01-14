# Windows Registry Monitor

Real-time Windows Registry monitoring system with a Go backend and a PyQt6 frontend.

## Components

1.  **Backend (Go)**: Monitors registry changes using Windows API (`RegNotifyChangeKeyValue`), batches events, and publishes them via ZeroMQ.
2.  **Frontend (Python)**: Subscribes to ZeroMQ, displays changes in a high-performance table, and provides export capabilities (.REG, CSV).

## Prerequisites

-   Windows 10 or 11 (64-bit)
-   Go 1.21+
-   Python 3.10+
-   Administrator privileges (required for registry access)

## Setup and Installation

### 1. Backend (Go)

```bash
# Initialize and install dependencies
go mod tidy

# Compile the backend
go build -o main.exe main.go
```

### 2. Frontend (Python)

```bash
# Install dependencies
pip install -r requirements.txt
```

## Running the Application

1.  **Start the Backend**:
    Open a terminal as **Administrator** and run:
    ```bash
    ./main.exe
    ```
    The backend will start monitoring `HKEY_CURRENT_USER` and `HKEY_LOCAL_MACHINE\SOFTWARE`.

2.  **Start the Frontend**:
    In another terminal, run:
    ```bash
    python app.py
    ```

3.  **Usage**:
    -   Click **Start Monitoring** in the UI.
    -   Perform some registry changes (e.g., via `regedit`) to see them appear.
    -   Use the **Exclusion Filter** to filter out noisy paths.
    -   Click **Export to .REG** to generate a report of all captured changes.

## Features

-   **High Performance**: Handles 500+ changes/sec with batching and Model/View pattern.
-   **Real-time Stats**: Displays total changes, changes/second, and filtered events.
-   **Smart Export**: Generates `.reg` files with three sections (NEW, MODIFIED, DELETED) and proper encoding (UTF-16 LE).
-   **Memory Efficient**: Frontend table is virtualized and limited to the last 5000 events.

## Important Notes

-   **Administrator Rights**: The backend **must** be run as Administrator to access protected registry keys.
-   **Performance**: `RegNotifyChangeKeyValue` triggers on any change in the subtree. The backend performs a comparison scan to identify specific value changes. To maintain performance, the scan depth is limited.
-   **Export Safety**: Always review `.reg` files before applying them. Deleted values are marked with `-` for safety.
