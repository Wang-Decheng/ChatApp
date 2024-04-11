import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QMessageBox, QVBoxLayout, QWidget, QStackedWidget, QTextEdit,  QHBoxLayout
from PyQt5.QtCore import Qt,  pyqtSignal
import socket
import json
import os
import threading
import logging
import time

sys.path.append(".")
from utils import MessageBuilder as mb



class CurrentUser:
    username = None  # 静态成员变量

    @staticmethod
    def set_username(username):
        CurrentUser.username = username
        
    @staticmethod
    def del_username():
        CurrentUser.username = None

    @staticmethod
    def get_username():
        return CurrentUser.username

class ChatConnection:
    def __init__(self, host, port, heartbeat_interval = 10):
        self.host = host
        self.port = port
        self.client_socket = None
        self.heartbeat_interval = heartbeat_interval
        self.lock = threading.Lock()
    def start_connect(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))
        threading.Thread(target=self.send_heartbeat).start()
        self.listen_to_server()

    def disconnect(self):
        with self.lock:
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
    
    def listen_to_server(self):
        listen_thread = threading.Thread(target=self.message_handler)
        listen_thread.start()
    
    def send_message(self, message):
        is_open_before = False
        if not self.client_socket:
            self.start_connect()
        else: is_open_before = True
        with self.lock:
            try:
                return self.client_socket.send(json.dumps(message).encode('utf-8'))
            except Exception as e:
                QMessageBox.critical(QMessageBox(), "Error", str(e))
        if not is_open_before: self.disconnect()
    
    def message_handler(self):
        while self.client_socket is not None:
            try:
                message_json = self.client_socket.recv(1024).decode('utf-8')
                message = json.loads(message_json)
                type = message['type']
                if type == 'response':
                    self.parent.response_signal.emit(message)
            except Exception as e:
                logging.error(f"Error receiving message:{str(e)}")
                self.disconnect()
                break
    
    def send_heartbeat(self):
        while self.client_socket is not None:
            try:
                username = CurrentUser.get_username()
                if username is not None:
                    message = mb.build_heartbeat(username)
                    self.send_message(message)
            except Exception as e:
                logging.error(f"Error sending heartbeat:{str(e)}")
            time.sleep(self.heartbeat_interval)

class ChatClient(QMainWindow):
    response_signal = pyqtSignal(dict)
    def __init__(self, host, port):
        super().__init__()

        self.connection = ChatConnection(host, port)
        self.host = host
        self.port = port
        self.client_socket = None
        self.lock = threading.Lock()
        self.username = None
        self.connection.parent = self
        
        self.response_signal.connect(self.show_response)
        # region 窗口组件
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
        # endregion
    # region 切换页面
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
    # end region    
    @staticmethod
    def clear_text(widget):
        if isinstance(widget, (QLineEdit, QTextEdit)):
            widget.clear()
        elif isinstance(widget, QWidget):
            for child in widget.findChildren((QLineEdit, QTextEdit)):
                child.clear()
    
    def show_response(self, response):
        if not response:return
        if response['success']:
            message = response['message']
            QMessageBox.information(self, "Success", message)
        else:
            error_message = response['message']
            QMessageBox.critical(self, "Error", error_message)
        return response['success']

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

        self.login_button.clicked.connect(parent.show_login_page)
        self.register_button.clicked.connect(parent.show_register_page)
        self.delete_button.clicked.connect(parent.show_delete_page)

        self.setLayout(layout)

class RegisterPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

        self.username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.register_button = QPushButton("Register")
        self.back_button = QPushButton("Back")

        self.register_button.clicked.connect(self.register_user)
        self.back_button.clicked.connect(parent.show_main_page)

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_entry)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.register_button)
        layout.addWidget(self.back_button)
        self.setLayout(layout)

    def register_user(self):
        username = self.username_entry.text()
        password = self.password_entry.text()
        if not username.strip() or not password.strip():
            QMessageBox.critical(self, "Error", "Username and password cannot be blank.")
            return
        message = mb.build_register_request(username, password)
        if self.parent.connection.send_message(message):
            self.parent.show_main_page()

class LoginPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

        self.username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.login_button = QPushButton("Login")
        self.back_button = QPushButton("Back")

        self.login_button.clicked.connect(self.login_user)
        self.back_button.clicked.connect(parent.show_main_page)

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_entry)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.login_button)
        layout.addWidget(self.back_button)
        self.setLayout(layout)

    def login_user(self):
        username = self.username_entry.text()
        password = self.password_entry.text()
        if not username.strip() or not password.strip():
            QMessageBox.critical(self, "Error", "Username and password cannot be blank.")
            return
        message = mb.build_login_request(username, password)
        if self.parent.connection.send_message(message):
            self.parent.show_chat_page()

class DeletePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

        self.username_label = QLabel("Username:")
        self.username_entry = QLineEdit()
        self.password_label = QLabel("Password:")
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.delete_button = QPushButton("Delete Account")
        self.back_button = QPushButton("Back")

        self.delete_button.clicked.connect(self.delete_account)
        self.back_button.clicked.connect(parent.show_main_page)

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_entry)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.delete_button)
        layout.addWidget(self.back_button)
        self.setLayout(layout)

    def delete_account(self):
        username = self.username_entry.text()
        password = self.password_entry.text()
        if not username.strip() or not password.strip():
            QMessageBox.critical(self, "Error", "Username and password cannot be blank.")
            return
        confirmation = QMessageBox.question(self, "Confirmation", "Are you sure you want to delete your account?",
                                    QMessageBox.Yes | QMessageBox.No)
        if confirmation == QMessageBox.Yes:
            message = mb.build_delete_request(username, password)
            if self.parent.connection.send_message(message):
                self.parent.show_main_page()

class ChatPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

        self.chat_label = QLabel("Chat Page")
        self.message_display = QLabel()
        self.message_display.setMinimumHeight(100)
        self.send_to_label = QLabel("Send to:")
        self.receiver_entry = QLineEdit()
        self.message_entry = QTextEdit()
        self.back_button = QPushButton("Back")
        self.send_message_button = QPushButton("Send Message") 

        self.back_button.clicked.connect(parent.show_main_page)
        self.send_message_button.clicked.connect(self.send_message)

        layout = QVBoxLayout()
        layout.addWidget(self.chat_label, alignment=Qt.AlignCenter)
        layout.addWidget(self.message_display)
        send_to_layout = QHBoxLayout()
        send_to_layout.addWidget(self.send_to_label)
        send_to_layout.addWidget(self.receiver_entry)
        layout.addLayout(send_to_layout)
        layout.addWidget(self.message_entry)
        layout.addWidget(self.send_message_button)
        layout.addWidget(self.back_button)
        self.setLayout(layout)

    def send_message(self):
        username = CurrentUser.get_username()
        reciver = self.receiver_entry.text()
        content = self.message_entry.toPlainText()
        message = mb.build_send_personal_message_request(username, reciver, content)
        self.parent.connection.send_message(message)

def config_logging(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'):
    logger = logging.getLogger()
    logger.setLevel(level)
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter(format)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        file_handler = logging.FileHandler('c-debug.log')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

if __name__ == '__main__':
    config_logging()
    if os.environ.get('LOCAL') == 'True':
        ip_address = '127.0.0.1'
    else:
        domain_name = "wdc.zone"
        ip_address = socket.gethostbyname(domain_name)
    app = QApplication(sys.argv)
    client = ChatClient(ip_address, 9999)
    client.show()
    sys.exit(app.exec_())