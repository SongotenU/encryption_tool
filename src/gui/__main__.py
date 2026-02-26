"""
Entry point for FileCrypt GUI application.

Run with: python -m src.gui
"""

import sys

from PyQt6.QtWidgets import QApplication

from src.gui.main_window import MainWindow

def main() -> int:
    """Launch the FileCrypt GUI application."""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
