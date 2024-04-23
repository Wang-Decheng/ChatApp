import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QMessageBox, QVBoxLayout, QWidget, QStackedWidget, QTextEdit, QHBoxLayout, QFileDialog
from PyQt5.QtCore import Qt, pyqtSignal
import socket
import json
import os
import threading
import logging
import time
import queue
from datetime import datetime
import struct
import pickle

sys.path.append(".")
from utils import MessageBuilder as mb

global_lock = threading.Lock()


class CurrentUser:
    username = None

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

    def __init__(self, host, port, heartbeat_interval=10, timeout=30):
        self.host = host
        self.port = port
        self.server_socket = None
        self.heartbeat_interval = heartbeat_interval
        self.timeout = timeout
        self.lock = threading.Lock()
        self.response_cache = None
        self.parent = None

    def start_connect(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.connect((self.host, self.port))
        listen_thread = threading.Thread(target=self.handle_server)
        listen_thread.start()
        threading.Thread(target=self.send_heartbeat).start()

    def disconnect(self):
        with self.lock:
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None

    def handle_server(self):
        last_heartbeat_time = datetime.now()
        self.server_socket.settimeout(15)
        while True:
            try:
                # message_json = self.server_socket.recv(1024).decode('utf-8')
                # logging.info(f"Received message: {message_json}")
                # message = json.loads(message_json)
                message_length = int.from_bytes(self.server_socket.recv(4), byteorder='big')
                message_bytes = self.server_socket.recv(message_length)
                message = pickle.loads(message_bytes)
                if message['type'] != 'file_data':
                    logging.info(f"Received message: {message}")

                last_heartbeat_time = datetime.now()
                message_type = message.get('type')
                if message_type == 'heartbeat':
                    logging.debug("Received heartbeat from server")
                elif message_type == 'response':
                    self.response_cache = message
                else:
                    self.handle_message(message)
            except socket.timeout:
                logging.debug("Socket timeout")
                if (datetime.now() - last_heartbeat_time).total_seconds() > self.timeout:
                    logging.info("Server timeout")
                self.disconnect()
            except json.JSONDecodeError:
                logging.error("Error decoding JSON message")
            except KeyError as e:
                logging.error(f"Missing key in message: {e}")

    def handle_message(self, message):
        if message['type'] == 'personal_message':
            sender = message['sender']
            content = message['content']
            timestamp = message['timestamp']
            timestamp_datetime = datetime.fromtimestamp(timestamp)
            formatted_timestamp = timestamp_datetime.strftime("%m-%d %H:%M")
            string = f"[{formatted_timestamp}]{sender}->You:\n{content}"
            self.parent.chat_page.display_message(string)

        if message['type'] == 'file_tranfer_header':
            file_path = os.path.dirname(__file__) + '\\' + message['file_name']
            with open(file_path, 'wb') as fp:
                pass

            self.parent.chat_page.display_message(
                message['file_name'] + ' ' + str(message['file_size'])
            )  # test 输出传输文件信息

        if message['type'] == 'file_data':
            file_path = os.path.dirname(__file__) + '\\' + message['file_name']
            with open(file_path, 'ab') as fp:
                data = message['file_content']
                fp.write(data)
            pass

    def send_message(self, message):
        if not self.server_socket:
            self.start_connect()
        with global_lock:
            try:
                message_json = json.dumps(message)
                logging.info(f"Sending message: {message_json}")
                # self.server_socket.send(message_json.encode('utf-8'))
                message_bytes = pickle.dumps(message)
                self.server_socket.send(len(message_bytes).to_bytes(4, byteorder='big'))
                self.server_socket.send(message_bytes)
            except Exception as e:
                logging.error(str(e))

    def send_heartbeat(self):
        while self.server_socket is not None:
            try:
                username = CurrentUser.get_username()
                if username is not None:
                    message = mb.build_heartbeat(username)
                    self.send_message(message)
            except Exception as e:
                logging.error(f"Error sending heartbeat:{str(e)}")
            time.sleep(self.heartbeat_interval)

    def get_response(self, request_timestamp, timelimit=1):
        start_time = time.time()
        while (self.response_cache is None or self.response_cache['timestamp'] < request_timestamp):
            if (time.time() - start_time > timelimit): break
        if self.response_cache['timestamp'] == request_timestamp:
            return self.response_cache
        else:
            return False, 'No Response'


class ChatClient(QMainWindow):
    response_signal = pyqtSignal(dict)

    def __init__(self, host, port):
        super().__init__()

        self.connection = ChatConnection(host, port)
        self.host = host
        self.port = port
        self.lock = threading.Lock()
        self.username = None
        self.connection.parent = self
        self.response_signal.connect(self.show_response)
        # region 窗口组件
        self.setWindowTitle("Chat Client")
        self.setGeometry(100, 100, 300, 150)
        self.setMinimumSize(400, 600)

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
        self.clear_text(self.chat_page)  # 在打开聊天页面时清理之前的聊天痕迹

    # end region
    @staticmethod
    def clear_text(widget):
        if isinstance(widget, (QLineEdit, QTextEdit)):
            widget.clear()
        elif isinstance(widget, QWidget):
            for child in widget.findChildren((QLineEdit, QTextEdit)):
                child.clear()

    def show_response(self, response):
        if not response: return
        if response['success']:
            message = response['message']
            QMessageBox.information(self, "Success", message)
        else:
            error_message = response['message']
            QMessageBox.critical(self, "Error", error_message)
        return response['success']

    def get_response(self, request_timestamp):
        return self.connection.get_response(request_timestamp)


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
        timestamp = message['timestamp']
        self.parent.connection.send_message(message)
        response = self.parent.get_response(timestamp)
        if self.parent.show_response(response):
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
        timestamp = message['timestamp']
        self.parent.connection.send_message(message)
        response = self.parent.get_response(timestamp)
        if self.parent.show_response(response):
            CurrentUser.set_username(username)
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
        confirmation = QMessageBox.question(
            self, "Confirmation", "Are you sure you want to delete your account?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirmation == QMessageBox.Yes:
            message = mb.build_delete_request(username, password)
            timestamp = message['timestamp']
            self.parent.connection.send_message(message)
            response = self.parent.get_response(timestamp)
            if self.parent.show_response(response):
                self.parent.show_main_page()


class ChatPage(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

        self.chat_label = QLabel("Chat Page")
        self.message_display = QTextEdit()
        self.message_display.setReadOnly(True)
        self.send_to_label = QLabel("Send to:")
        self.receiver_entry = QLineEdit()
        self.message_entry = QTextEdit()
        self.back_button = QPushButton("Back")
        self.send_message_button = QPushButton("Send Message")
        self.send_file_button = QPushButton("Send File")

        self.back_button.clicked.connect(parent.show_main_page)
        self.send_message_button.clicked.connect(self.send_message)
        self.send_file_button.clicked.connect(self.send_file)

        layout = QVBoxLayout()
        layout.addWidget(self.chat_label, alignment=Qt.AlignCenter)
        layout.addWidget(self.message_display)
        send_to_layout = QHBoxLayout()
        send_to_layout.addWidget(self.send_to_label)
        send_to_layout.addWidget(self.receiver_entry)
        layout.addLayout(send_to_layout)
        layout.addWidget(self.message_entry)
        layout.addWidget(self.send_message_button)
        layout.addWidget(self.send_file_button)
        layout.addWidget(self.back_button)
        self.setLayout(layout)

    def send_message(self):
        username = CurrentUser.get_username()
        reciver = self.receiver_entry.text()
        if username != reciver:
            content = self.message_entry.toPlainText()
            message = mb.build_send_personal_message_request(username, reciver, content)
            timestamp = message['timestamp']
            self.parent.connection.send_message(message)
            response = self.parent.get_response(timestamp)
        else:
            response = {'success': False, 'message': 'Can not send to yourself'}

        if response['success']:
            receiver = message['request_data']['receiver']
            content = message['request_data']['content']
            formatted_timestamp = datetime.fromtimestamp(message['timestamp']).strftime("%m-%d %H:%M")
            self.display_message(f"[{formatted_timestamp}]You->{receiver}:\n{content}")
        self.parent.show_response(response)

    def display_message(self, message):
        message = message + '\n'
        self.message_display.append(message)

    def send_file(self):  # TODO
        username = CurrentUser.get_username()
        receiver = self.receiver_entry.text()
        response = None

        while True:
            if not receiver:  # 若没有输入接收者，则返回
                response = {'success': False, 'message': 'Please input the receiver username'}
                break
            if username == receiver:  # 若输入的接收者是自己，则返回
                response = {'success': False, 'message': 'Can not send file to yourself'}
                break

            options = QFileDialog.Options()
            file_path, _ = QFileDialog.getOpenFileName(self, "文件选择", "", "All Files (*)", options=options)
            if not file_path:  # 若没有选择文件，则返回
                response = {'success': False, 'message': 'No file selected'}
                break

            if not os.path.isfile(file_path):
                response = {'success': False, 'message': 'It\'s not File'}
                break

            request = mb.build_file_transfer_header(
                username, receiver, os.path.basename(file_path),
                os.stat(file_path).st_size, None
            )
            timestamp = request['timestamp']
            self.parent.connection.send_message(request)
            response = self.parent.get_response(timestamp)

            if not response['success']:
                break

            threading.Thread(
                target=self.__send_file_content, args=(username, receiver, file_path), daemon=True
            ).start()

            # with open(file_path, "rb") as fp:
            #     while True:
            #         data = fp.read(2000)
            #         if not data:
            #             break
            #         file_data_packet = mb.build_file_data(
            #             username, receiver, os.path.basename(file_path), data
            #         )
            #         self.parent.connection.send_message(file_data_packet)

            self.display_message(f'File {os.path.basename(file_path)} prepared to send.')  # test

            break

        # self.parent.show_response(response)

    def __send_file_content(self, username, receiver, file_path):
        with open(file_path, 'rb') as fp:
            while True:
                data = fp.read(4000)
                if not data:
                    break
                file_data_packet = mb.build_file_data(username, receiver, os.path.basename(file_path), data)
                self.parent.connection.send_message(file_data_packet)

        self.display_message(f"File {os.path.basename(file_path)} sent successfully.")


def config_logging(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'):
    logger = logging.getLogger()
    logger.setLevel(level)
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter(format)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        args = sys.argv
        if len(args) >= 1:
            logfilename = args[1] + '-debug.log'
        else:
            logfilename = 'c-debug.log'
        file_handler = logging.FileHandler(logfilename)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)


def debug_func(client):
    connection = client.connection
    args = sys.argv
    if len(args) >= 1:
        username = 'user' + args[1]
    else:
        username = 'user'
    password = '123'
    register_msg = mb.build_register_request(username, password)
    login_msg = mb.build_login_request(username, password)
    connection.send_message(register_msg)
    time.sleep(1)
    connection.send_message(login_msg)
    CurrentUser.set_username(username)
    client.show_chat_page()
    client.setWindowTitle(username)


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
    if os.environ.get('DEBUG') == 'True':
        debug_func(client)
    sys.exit(app.exec_())
