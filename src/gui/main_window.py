"""
Main application window for FileCrypt.

Provides a drag-and-drop interface for encrypting and decrypting files.
"""

from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDragEnterEvent, QDropEvent
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.crypto import decrypt_file, encrypt_file


class DropZone(QLabel):
    """A label widget that accepts file drops."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setMinimumHeight(150)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setText("Drop a file here to encrypt or decrypt")
        self.setStyleSheet("""
            QLabel {
                background-color: #f5f5f5;
                border: 2px dashed #aaa;
                border-radius: 10px;
                font-size: 14px;
                color: #666;
            }
        """)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        """Accept drag events only for file URLs."""
        if event.mimeData().hasUrls():
            # Check if any URL is a local file
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        """Handle file drop - emit signal with file path."""
        if event.mimeData().hasUrls():
            # Get the first local file
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    file_path = url.toLocalFile()
                    # Use parent MainWindow method if available
                    if hasattr(self.parent(), 'handle_file_drop'):
                        self.parent().handle_file_drop(file_path)
                    break


class MainWindow(QMainWindow):
    """Main application window for FileCrypt."""

    def __init__(self):
        super().__init__()

        # Window setup
        self.setWindowTitle("FileCrypt")
        self.setMinimumSize(500, 400)
        self.setAcceptDrops(True)

        # State
        self._current_file: Optional[Path] = None
        self._is_encrypt_mode: bool = True

        # Build UI
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Drop zone
        self._drop_zone = DropZone(self)
        layout.addWidget(self._drop_zone)

        # Select file button
        self._select_button = QPushButton("Select File")
        self._select_button.setMinimumHeight(40)
        self._select_button.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        self._select_button.clicked.connect(self._on_select_file)
        layout.addWidget(self._select_button)
        # Mode indicator
        self._mode_label = QLabel("Mode: Ready")
        self._mode_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._mode_label.setStyleSheet("font-size: 12px; color: #888;")
        layout.addWidget(self._mode_label)

        # File info display (initially hidden)
        self._file_label = QLabel()
        self._file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._file_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #333;
                padding: 10px;
                background-color: #e8f4e8;
                border-radius: 5px;
            }
        """)
        self._file_label.hide()
        layout.addWidget(self._file_label)

        # Action button (initially disabled)
        self._action_button = QPushButton("Encrypt")
        self._action_button.setEnabled(False)
        self._action_button.setMinimumHeight(40)
        self._action_button.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                font-weight: bold;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #888;
            }
        """)
        self._action_button.clicked.connect(self._on_action_clicked)
        layout.addWidget(self._action_button)

        # Delete original file checkbox
        self._delete_checkbox = QCheckBox("Delete original file after operation")
        self._delete_checkbox.setStyleSheet("font-size: 12px; color: #666;")
        layout.addWidget(self._delete_checkbox)

        # Progress bar (initially hidden)
        self._progress_bar = QProgressBar()
        self._progress_bar.setMinimum(0)
        self._progress_bar.setMaximum(0)  # Indeterminate mode
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setMinimumHeight(5)
        self._progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #f0f0f0;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 3px;
            }
        """)
        self._progress_bar.hide()
        layout.addWidget(self._progress_bar)

        # Status label
        self._status_label = QLabel("Ready - Drop a file to begin")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setStyleSheet("font-size: 11px; color: #666;")
        layout.addWidget(self._status_label)

        # Clear button
        self._clear_button = QPushButton("Clear")
        self._clear_button.setMinimumHeight(30)
        self._clear_button.setStyleSheet("""
            QPushButton {
                font-size: 12px;
                background-color: #f44336;
                color: white;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
        """)
        self._clear_button.clicked.connect(self.reset_ui)
        layout.addWidget(self._clear_button)

        # Spacer
        layout.addStretch()

    def _on_select_file(self) -> None:
        """Open file dialog to select a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select a file to encrypt or decrypt",
            "",
            "All Files (*)"
        )
        if file_path:
            self.handle_file_drop(file_path)
    def handle_file_drop(self, file_path: str) -> None:
        """Handle a file being dropped onto the drop zone."""
        path = Path(file_path)
        
        if not path.exists():
            self.show_error(f"File not found: {file_path}")
            return

        self._current_file = path
        
        # Determine mode based on extension
        self._is_encrypt_mode = not path.suffix.lower() == '.fcrypt'
        
        # Update UI
        self._file_label.setText(f"File: {path.name}")
        self._file_label.show()
        
        mode_text = "Encrypt" if self._is_encrypt_mode else "Decrypt"
        self._mode_label.setText(f"Mode: {mode_text}")
        self._mode_label.setStyleSheet(f"""
            font-size: 12px; 
            color: {'#4CAF50' if self._is_encrypt_mode else '#2196F3'};
            font-weight: bold;
        """)
        
        self._action_button.setText(mode_text)
        self._action_button.setEnabled(True)
        self._status_label.setText(f"Ready to {mode_text.lower()}")
        self._status_label.setStyleSheet("font-size: 11px; color: #666;")

    def _on_action_clicked(self) -> None:
        """Handle encrypt/decrypt button click."""
        if self._current_file is None:
            return

        # Import here to avoid circular import
        from .password_dialog import PasswordDialog

        # Get password from user
        password, accepted = PasswordDialog.get_password_from_user(self)
        
        if not accepted or not password:
            return

        # Perform operation
        self._perform_operation(password)

    def _perform_operation(self, password: str) -> None:
        """Perform encrypt or decrypt operation."""
        if self._current_file is None:
            return

        # Show progress
        self._progress_bar.show()
        self._action_button.setEnabled(False)
        
        operation = "Encrypting" if self._is_encrypt_mode else "Decrypting"
        self._status_label.setText(f"{operation}...")
        self._status_label.setStyleSheet("font-size: 11px; color: #2196F3; font-weight: bold;")

        try:
            if self._is_encrypt_mode:
                output_path = encrypt_file(self._current_file, password=password)
            else:
                output_path = decrypt_file(self._current_file, password=password)

            # Delete original file if checkbox is checked
            if self._delete_checkbox.isChecked():
                reply = QMessageBox.question(
                    self,
                    "Delete Original File",
                    f"Delete the original file?\n\n{self._current_file.name}",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.Yes:
                    self._current_file.unlink()
                    self.show_success(f"Success!\nCreated: {output_path.name}\nOriginal deleted.")
                else:
                    self.show_success(f"Success!\nCreated: {output_path.name}")
            else:
                self.show_success(f"Success!\nCreated: {output_path.name}")

        except FileNotFoundError as e:
            self.show_error(f"File error: {e}")
        except ValueError as e:
            # Generic error for decryption failures (wrong password, corrupted file)
            self.show_error(str(e))
        except Exception as e:
            self.show_error(f"Unexpected error: {e}")
        finally:
            self._progress_bar.hide()

    def show_success(self, message: str) -> None:
        """Display a success message."""
        self._status_label.setText(message)
        self._status_label.setStyleSheet("""
            font-size: 11px; 
            color: #4CAF50; 
            font-weight: bold;
            background-color: #e8f5e9;
            padding: 5px;
            border-radius: 3px;
        """)

    def show_error(self, message: str) -> None:
        """Display an error message."""
        self._status_label.setText(f"Error: {message}")
        self._status_label.setStyleSheet("""
            font-size: 11px; 
            color: #f44336; 
            font-weight: bold;
            background-color: #ffebee;
            padding: 5px;
            border-radius: 3px;
        """)
        # Re-enable action button so user can retry
        self._action_button.setEnabled(True)

    def reset_ui(self) -> None:
        """Reset the UI to initial state."""
        self._current_file = None
        self._is_encrypt_mode = True
        
        self._file_label.hide()
        self._progress_bar.hide()
        self._mode_label.setText("Mode: Ready")
        self._mode_label.setStyleSheet("font-size: 12px; color: #888;")
        self._action_button.setText("Encrypt")
        self._action_button.setEnabled(False)
        self._status_label.setText("Ready - Drop a file to begin")
        self._status_label.setStyleSheet("font-size: 11px; color: #666;")


def main():
    """Application entry point."""
    app = QApplication([])
    win = MainWindow()
    win.show()
    app.exec()


if __name__ == "__main__":
    main()
