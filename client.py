import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QDialog, QLabel, QLineEdit, QPushButton, QMessageBox, QVBoxLayout, QWidget, QInputDialog, QStackedWidget
from PyQt5.QtCore import Qt
import socket
import json

class ChatClient(QMainWindow):
    def __init__(self, host, port):
        super().__init__()

        self.host = host
        self.port = port

        self.setWindowTitle("Chat Client")
        self.setGeometry(100, 100, 300, 150)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_page = LoginPage(self)
        self.delete_account_page = DeleteAccountPage(self)
        self.stack.addWidget(self.login_page)
        self.stack.addWidget(self.delete_account_page)

        self.login_page.register_button.clicked.connect(self.register_user)
        self.login_page.login_button.clicked.connect(self.login_user)
        self.login_page.delete_account_button.clicked.connect(self.open_delete_account_page)

    def register_user(self):
        username = self.login_page.username_entry.text()
        password = self.login_page.password_entry.text()
        self.send_request({'action': 'register', 'username': username, 'password': password})

    def login_user(self):
        username = self.login_page.username_entry.text()
        password = self.login_page.password_entry.text()
        self.send_request({'action': 'login', 'username': username, 'password': password})

    def open_delete_account_page(self):
        self.stack.setCurrentIndex(1)

    def send_request(self, request_data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            try:
                client_socket.connect((self.host, self.port))
                client_socket.send(json.dumps(request_data).encode('utf-8'))
                response = client_socket.recv(1024).decode('utf-8')
                response_data = json.loads(response)
                if response_data['success']:
                    message = response_data['message']
                    QMessageBox.information(self, "Success", message)
                else:
                    error_message = response_data['message']
                    QMessageBox.critical(self, "Error", error_message)
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

class LoginPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.register_button = QPushButton("Register")
        self.login_button = QPushButton("Login")
        self.delete_account_button = QPushButton("Delete Account")

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_entry)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.register_button)
        layout.addWidget(self.login_button)
        layout.addWidget(self.delete_account_button)

        self.setLayout(layout)

class DeleteAccountPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.delete_button = QPushButton("Delete Account")

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_entry)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.delete_button)

        self.setLayout(layout)

        self.delete_button.clicked.connect(self.delete_account)

    def delete_account(self):
        username = self.username_entry.text()
        password = self.password_entry.text()

        # 弹出确认对话框
        confirmation, ok = QInputDialog.getText(self, "Confirmation", "Type 'DELETE' to confirm account deletion:", QLineEdit.Normal, "")
        
        # 检查确认字符串
        if ok and confirmation == 'DELETE':
            # 从父级窗口获取 ChatClient 实例，并调用其 send_request 方法
            parent_client = self.parent().parent()
            success, message = parent_client.send_request({'action': 'delete_account', 'password': password})
            if success:
                QMessageBox.information(self, "Success", message)
            else:
                QMessageBox.critical(self, "Error", message)
        else:
            QMessageBox.information(self, "Confirmation", "Account deletion canceled.")

if __name__ == '__main__':
    domain_name = "wdc.zone"
    ip_address = socket.gethostbyname(domain_name)
    app = QApplication(sys.argv)
    client = ChatClient(ip_address, 9999)
    client.show()
    sys.exit(app.exec_())
