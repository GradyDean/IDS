from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLabel
from PySide6.QtCore import Qt
import json

class AlertDisplay(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDS Alert Display")
        self.setGeometry(100, 100, 800, 600)
        
        # Create layout
        layout = QVBoxLayout()
        
        # Add title
        title = QLabel("Intrusion Detection System Alerts")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Add text area for alerts
        self.alert_text = QTextEdit()
        self.alert_text.setReadOnly(True)
        layout.addWidget(self.alert_text)
        
        self.setLayout(layout)
    
    def add_alert(self, alert):
        """Add a new alert to the display."""
        alert_text = json.dumps(alert, indent=2)
        self.alert_text.append(f"\n=== New Alert ===\n{alert_text}\n")
        self.show() 