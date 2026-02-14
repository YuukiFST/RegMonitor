# RegMonitor

A lightweight, real-time Windows Registry monitoring tool.

## Usage

1. Run `RegMonitor.exe` (as Administrator).
2. **Start Monitoring** to begin tracking changes.
3. **Filter** paths to reduce noise.
4. **Export to .REG** to save captured changes (clean, importable format).

## About

Built with **Rust** and **Python/PyQt6**.

- **Real-time:** Instantly detects new, modified, and deleted keys/values.
- **Efficient:** Uses low-level Windows APIs (`RegNotifyChangeKeyValue`) for minimal overhead.
- **Portable:** Single executable with no external dependencies.
