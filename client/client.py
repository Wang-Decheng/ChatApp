import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QDialog, QLabel, QLineEdit, QPushButton, QMessageBox, QVBoxLayout, QWidget, QStackedWidget, QTextEdit
from PyQt5.QtCore import Qt
import socket
import json
import os

sys.path.append(".")
import utils


class ChatClient(QMainWindow):
    def __init__(self, host, port):
        super().__init__()

        self.host = host
        self.port = port

        self.setWindowTitle("Chat Client")
        self.setGeometry(100, 100, 300, 150)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.main_page = MainPage(self)
        self.register_page = RegisterPage(self)
        self.login_page = LoginPage(self)
        self.delete_page = DeletePage(self)
        self.chat_page = ChatPage(self)

        self.stack.addWidget(self.main_page)
        self.stack.addWidget(self.register_page)
        self.stack.addWidget(self.login_page)
        self.stack.addWidget(self.delete_page)
        self.stack.addWidget(self.chat_page)

        self.main_page.login_button.clicked.connect(self.show_login_page)
        self.main_page.register_button.clicked.connect(self.show_register_page)
        self.main_page.delete_button.clicked.connect(self.show_delete_page)

        self.register_page.register_button.clicked.connect(self.register_user)
        self.register_page.back_button.clicked.connect(self.show_main_page)

        self.login_page.login_button.clicked.connect(self.login_user)
        self.login_page.back_button.clicked.connect(self.show_main_page)

        self.delete_page.delete_button.clicked.connect(self.delete_account)
        self.delete_page.back_button.clicked.connect(self.show_main_page)

        self.chat_page.back_button.clicked.connect(self.show_main_page)

    def show_login_page(self):
        self.stack.setCurrentWidget(self.login_page)
        self.clear_text(self.login_page)

    def show_register_page(self):
        self.stack.setCurrentWidget(self.register_page)
        self.clear_text(self.register_page)

    def show_delete_page(self):
        self.stack.setCurrentWidget(self.delete_page)
        self.clear_text(self.delete_page)

    def show_main_page(self):
        self.stack.setCurrentWidget(self.main_page)

    def show_chat_page(self):
        self.stack.setCurrentWidget(self.chat_page)

    def register_user(self):
        username = self.register_page.username_entry.text()
        password = self.register_page.password_entry.text()
        if not username.strip() or not password.strip():
            QMessageBox.critical(self, "Error", "Username and password cannot be blank.")
            return
        if self.send_request({'action': 'register', 'username': username, 'password': password}):
            self.show_main_page()

    def login_user(self):
        username = self.login_page.username_entry.text()
        password = self.login_page.password_entry.text()
        if not username.strip() or not password.strip():
            QMessageBox.critical(self, "Error", "Username and password cannot be blank.")
            return
        if self.send_request({'action': 'login', 'username': username, 'password': password}):
            self.show_chat_page()

    def delete_account(self):
        username = self.delete_page.username_entry.text()
        password = self.delete_page.password_entry.text()
        if not username.strip() or not password.strip():
            QMessageBox.critical(self, "Error", "Username and password cannot be blank.")
            return
        confirmation = QMessageBox.question(self, "Confirmation", "Are you sure you want to delete your account?",
                                    QMessageBox.Yes | QMessageBox.No)
        if confirmation == QMessageBox.Yes:
            if self.send_request({'action': 'delete_account', 'username': username, 'password': password}):
                self.show_main_page()

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
                return response_data['success']
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))
    @staticmethod
    def clear_text(widget):
        if isinstance(widget, (QLineEdit, QTextEdit)):
            widget.clear()
        elif isinstance(widget, QWidget):
            for child in widget.findChildren((QLineEdit, QTextEdit)):
                child.clear()



class MainPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.login_button = QPushButton("Login")
        self.register_button = QPushButton("Register")
        self.delete_button = QPushButton("Delete Account")

        layout = QVBoxLayout()
        layout.addWidget(self.login_button)
        layout.addWidget(self.register_button)
        layout.addWidget(self.delete_button)
        self.setLayout(layout)


class RegisterPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.register_button = QPushButton("Register")
        self.back_button = QPushButton("Back")

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_entry)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.register_button)
        layout.addWidget(self.back_button)
        self.setLayout(layout)


class LoginPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.login_button = QPushButton("Login")
        self.back_button = QPushButton("Back")

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_entry)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.login_button)
        layout.addWidget(self.back_button)
        self.setLayout(layout)


class DeletePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.delete_button = QPushButton("Delete Account")
        self.back_button = QPushButton("Back")

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_entry)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.delete_button)
        layout.addWidget(self.back_button)
        self.setLayout(layout)


class ChatPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.chat_label = QLabel("Chat Page")
        self.back_button = QPushButton("Back")

        layout = QVBoxLayout()
        layout.addWidget(self.chat_label, alignment=Qt.AlignCenter)
        layout.addWidget(self.back_button)
        self.setLayout(layout)


if __name__ == '__main__':
    if os.environ.get('LOCAL') == 'True':
        ip_address = '127.0.0.1'
    else:
        domain_name = "wdc.zone"
        ip_address = socket.gethostbyname(domain_name)
    app = QApplication(sys.argv)
    client = ChatClient(ip_address, 9999)
    client.show()
    sys.exit(app.exec_())
