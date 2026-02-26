"""
Password input dialog for FileCrypt.

Provides a secure password entry dialog with masked input.
"""

from typing import Optional, Tuple

from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)


class PasswordDialog(QDialog):
    """Dialog for password input."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)

        self.setWindowTitle("Enter Password")
        self.setFixedSize(350, 120)

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        # Label
        label = QLabel("Enter password:")
        layout.addWidget(label)

        # Password input (masked)
        self._password_input = QLineEdit()
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_input.setPlaceholderText("Password")
        self._password_input.setMinimumHeight(30)
        layout.addWidget(self._password_input)

        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def get_password(self) -> str:
        """Return the entered password."""
        return self._password_input.text()

    @staticmethod
    def get_password_from_user(parent: Optional[QWidget] = None) -> Tuple[str, bool]:
        """
        Show the dialog and return the password and acceptance status.
        
        Returns:
            Tuple of (password, accepted) where accepted is True if user clicked OK.
        """
        dialog = PasswordDialog(parent)
        result = dialog.exec()
        
        if result == QDialog.DialogCode.Accepted:
            return dialog.get_password(), True
        return "", False
