import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QMessageBox, QVBoxLayout, QWidget, QStackedWidget, QTextEdit, QHBoxLayout, QFileDialog, QListWidget, QInputDialog
from PyQt5.QtCore import Qt, pyqtSignal, QThread
import socket
import json
import os
import threading
import logging
import time
import queue
from datetime import datetime
import concurrent.futures
import configparser

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

        self.friend_status_cache = None
        self.stop_flag = False

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
        config = Config()
        default_chunk_size = config.default_chunk_size
        while True:
            try:
                if self.server_socket is None: 
                    logging.warning("Server socket not connected")
                    break
                json_data = self.server_socket.recv(10 * default_chunk_size).decode('utf-8')
                message_json_list = json_data.split('!@#')
                for message_json in message_json_list[:-1]: #忽略最后的空包
                    logging.info(f"Received message: {message_json}")
                    message = json.loads(message_json)
                    last_heartbeat_time = datetime.now()
                    message_type = message.get('type')
                    if message_type == 'heartbeat':
                        logging.debug("Received heartbeat from server")
                    elif message_type == 'response':
                        self.response_cache = message  # FIXME
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
            except Exception as e:
                logging.error(str(e))

    def handle_message(self, message):  # TODO 收到消息后在此进行处理
        if message.get('action') is not None:  # 对数据进行拆包
            message = message['request_data']

        if message['type'] == 'personal_message':
            sender = message['sender']
            content = message['content']
            timestamp = message['timestamp']
            timestamp_datetime = datetime.fromtimestamp(timestamp)
            formatted_timestamp = timestamp_datetime.strftime("%m-%d %H:%M")
            string = f"[{formatted_timestamp}]{sender}->You:\n{content}"
            self.parent.chat_page.display_message(string, sender)

        if message.get('type') == 'file_transfer':  # TODO 处理文件传输头
            self.parent.chat_page.receive_file(message.get('file_name'), message.get('sender'))
            pass

    def send_message(self, message):
        if not self.server_socket:
            self.start_connect()
        with self.lock:
            try:
                if not self.server_socket: 
                    logging.error("Server socket not connected")
                    return
                message_json = json.dumps(message)
                logging.info(f"Sending message: {message_json}")
                message_json = message_json + '!@#'
                self.server_socket.send(message_json.encode('utf-8'))
                # message_bytes = pickle.dumps(message)
                # self.server_socket.send(len(message_bytes).to_bytes(4, byteorder='big'))
                # self.server_socket.send(message_bytes)
            except Exception as e:
                logging.error(str(e))

    def send_heartbeat(self):
        while self.server_socket is not None:
            try:
                if self.server_socket is None: break
                username = CurrentUser.get_username()
                if username is not None:
                    message = mb.build_heartbeat(username)
                    self.send_message(message)
            except Exception as e:
                logging.error(f"Error sending heartbeat:{str(e)}")
            time.sleep(self.heartbeat_interval)

    def get_response(self, request_timestamp, timelimit=5):  # FIXME
        start_time = time.time()
        while True:
            time.sleep(0.2)
            if self.response_cache is None: continue
            if self.response_cache['timestamp'] == request_timestamp: return self.response_cache
            if (time.time() - start_time > timelimit): break
        return False


class ChatClient(QMainWindow):
    response_signal = pyqtSignal(dict)  # MARK

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
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(self.connection.get_response, request_timestamp)
            return future.result()


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


class FileTransferThread(QThread):
    finished = pyqtSignal()

    pass


class ChatPage(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent

        self.setMinimumSize(900, 800)

        self.current_friend = None
        self.chat_pages = QStackedWidget()
        self.friend_list = QListWidget()
        self.init_UI()

        # threading.Thread(target=self.__update_friend_status, daemon=True).start()

    def init_UI(self):
        layout = QHBoxLayout(self)

        V_layout = QVBoxLayout()
        update_friends_list_button = QPushButton("Update List")
        update_friends_list_button.clicked.connect(self.__update_friend_status)
        update_friends_list_button.setFixedWidth(150)
        update_friends_list_button.setStyleSheet("QPushButton{text-align:left;}")
        V_layout.addWidget(update_friends_list_button)
        V_layout.addWidget(self.friend_list)
        layout.addLayout(V_layout)
        friend_list = ['None']
        self.friend_list.addItems(friend_list)
        self.friend_list.setFixedWidth(150)
        self.friend_list.itemClicked.connect(self.__change_selected_friend)
        # layout.addWidget(self.friend_list)

        for friend in friend_list:
            chat = self.__chatpage_factory(friend)
            if chat is not None:
                self.chat_pages.addWidget(chat)
        layout.addWidget(self.chat_pages)

        self.setLayout(layout)
        self.setWindowTitle("Chat Page")

        pass

    def __change_selected_friend(self, item):
        '''
        更改当前好友选择
        '''
        friend_name = item.text()
        self.current_friend = friend_name
        self.chat_pages.setCurrentWidget(self.chat_pages.findChild(QWidget, friend_name))

    def __chatpage_factory(self, friend_name: str):
        '''
        根据名字生成聊天界面
        '''
        chat = QWidget()  # 当前好友聊天界面
        chat.setObjectName(friend_name)

        min_width = 400
        min_height = 180

        layout = QVBoxLayout()

        # 当前好友状态显示
        chat.setProperty('status', 'offline')
        status_label = QLabel(f'{friend_name}状态:' + chat.property('status'))
        status_label.setObjectName('StatusLabel')
        status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(status_label)

        # 聊天消息显示
        message_displayer = QTextEdit()
        message_displayer.setReadOnly(True)
        message_displayer.setObjectName('MessageDisplayer')
        message_displayer.setMinimumWidth(min_width)
        message_displayer.setMinimumHeight(min_height)
        layout.addWidget(message_displayer)

        # 发送消息编辑框
        message_editor = QTextEdit()
        message_editor.setObjectName('MessageEditor')
        message_editor.setMinimumWidth(min_width)
        message_editor.setMinimumHeight(min_height)
        layout.addWidget(message_editor)

        button_layout = QHBoxLayout()
        # 发送消息按钮
        send_message_button = QPushButton("Send Message")
        send_message_button.setObjectName('SendMessageButton')
        send_message_button.clicked.connect(self.send_message)
        # send_message_button.setFixedSize(200, 30)
        button_layout.addWidget(send_message_button)
        # 发送文件按钮
        send_file_button = QPushButton("Send File")
        send_file_button.setObjectName('SendFileButton')
        send_file_button.clicked.connect(self.send_file)
        # send_file_button.setFixedSize(200, 30)
        button_layout.addWidget(send_file_button)

        layout.addLayout(button_layout)

        del button_layout
        button_layout = QHBoxLayout()
        # 添加好友按钮
        add_friend_button = QPushButton("Add Friend")
        add_friend_button.setObjectName('AddFriendButton')
        add_friend_button.clicked.connect(self.add_friend)
        button_layout.addWidget(add_friend_button)
        # 删除好友按钮
        delete_friend_button = QPushButton("Delete Friend")
        delete_friend_button.setObjectName('DeleteFriendButton')
        delete_friend_button.clicked.connect(self.remove_friend)
        button_layout.addWidget(delete_friend_button)

        layout.addLayout(button_layout)
        # 返回主界面按钮
        back_button = QPushButton("Back")
        back_button.setObjectName('BackButton')
        back_button.clicked.connect(self.__log_out)
        layout.addWidget(back_button)

        chat.setLayout(layout)

        return chat

    def __update_friend_status(self):
        # XXX 由于使用多线程时无法运行，所以在调用display_message时更新好友列表

        # while True:
        update_friend_list_request = mb.build_get_friends_request(CurrentUser.get_username())
        self.parent.connection.send_message(update_friend_list_request)
        response = self.parent.get_response(update_friend_list_request['timestamp'])
        if response is None or not response:
            # continue
            return

        if isinstance(response, bool):
            return

        if response['success']:

            friend_list = response['data']
            if friend_list is None:
                # continue
                return

            for index in range(self.friend_list.count()):  # 遍历好友列表，删除好友
                item = self.friend_list.item(index)
                username = item.text()

                status = friend_list.get(username)
                if status == None:
                    # 好友已经被删除
                    if username != 'None':
                        self.handle_delete_friend(username)

                else:
                    chat = self.chat_pages.findChild(QWidget, username)
                    chat.setProperty('status', status)
                    status_label = chat.findChild(QLabel, 'StatusLabel')
                    status_label.setText(f'{username}状态:{status}')

            for key, value in friend_list.items():
                if self.friend_list.findItems(key, Qt.MatchExactly):  # 好友列表存在该好友
                    continue

                chat = self.__chatpage_factory(key)
                chat.setProperty('status', value)
                label = chat.findChild(QLabel, 'StatusLabel')
                label.setText(f'{key}状态:{value}')

                self.friend_list.addItem(key)
                self.chat_pages.addWidget(chat)

            # time.sleep(10)

    def __log_out(self):
        self.parent.connection.send_message(mb.build_logout_request(CurrentUser.get_username()))
        self.parent.connection.disconnect()
        self.parent.show_main_page()
        pass

    def add_friend(self, friend_name):
        user_name, status = QInputDialog.getText(self, "Add Friend", "Enter the username of the friend:")
        if status == False:
            return

        add_friend_request = mb.build_add_friend_request(CurrentUser.get_username(), user_name)
        self.parent.connection.send_message(add_friend_request)

        timestamp = add_friend_request['timestamp']
        response = self.parent.get_response(timestamp)  # 单向添加好友
        if response is None or not response['success']:
            QMessageBox.critical(self, "Error", "Failed to add friend.")
            return

        chat = self.__chatpage_factory(user_name)
        self.friend_list.addItem(user_name)
        self.chat_pages.addWidget(chat)

    def remove_friend(self, friend_name):
        user_name, status = QInputDialog.getText(self, "Delete Friend", "Enter the username of the friend:")
        if status == False:
            return

        if user_name == self.current_friend:
            QMessageBox.critical(
                self, "Error", "You cannot delete your friend who you are currently chatting with."
            )
            return

        remove_friend_request = mb.build_remove_friend_request(CurrentUser.get_username(), user_name)
        self.parent.connection.send_message(remove_friend_request)

        timestamp = remove_friend_request['timestamp']
        response = self.parent.get_response(timestamp)  # 单向删除好友
        if response is None or not response:
            QMessageBox.critical(self, "Error", "Failed to remove friend.")
            return

        self.handle_delete_friend(user_name)

    def handle_add_friend(self, user_name):
        for i in range(self.friend_list.count()):  # 遍历好友列表
            if self.friend_list.item(i).text() == user_name:
                return

        chat = self.__chatpage_factory(user_name)
        self.friend_list.addItem(user_name)
        self.chat_pages.addWidget(chat)

    def handle_delete_friend(self, user_name):

        index = self.chat_pages.findChild(QWidget, user_name)
        self.chat_pages.removeWidget(index)
        index.deleteLater()

        index = self.friend_list.findItems(user_name, Qt.MatchExactly)
        for item in index:
            self.friend_list.takeItem(self.friend_list.row(item))

        if user_name == self.current_friend:
            page = self.friend_list.findItems("None", Qt.MatchExactly)
            self.__change_selected_friend(page[0])

    def send_message(self):
        if self.current_friend is None:
            QMessageBox.critical(self, "Error", "Please select a friend to send message.")
            return

        editor = self.chat_pages.currentWidget().findChild(QTextEdit, 'MessageEditor')
        displayer = self.chat_pages.currentWidget().findChild(QTextEdit, 'MessageDisplayer')
        friend_name = self.current_friend

        message = editor.toPlainText()
        if message == '':
            return

        if self.current_friend == 'None':
            self.display_message(message, friend_name)
            return

        message_packet = mb.build_send_personal_message_request(
            CurrentUser.get_username(), friend_name, message
        )
        self.parent.connection.send_message(message_packet)
        self.display_message(message, friend_name)

        editor.clear()  # 清空编辑框

    def display_message(self, message, target=None):
        chat = self.chat_pages.findChild(QWidget, target)
        if chat is None:
            return

        displayer = chat.findChild(QTextEdit, 'MessageDisplayer')
        displayer.append(message + '\n')
        displayer.moveCursor(displayer.textCursor().End)

        # self.__update_friend_status()

    def send_file(self):  # TODO 使用QThread发送、接收文件，完毕后弹窗
        if self.current_friend is None:
            QMessageBox.critical(self, "Error", "Please select a friend to send file.")
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "文件选择", "", "All Files (*)")
        if not file_path:
            return

        sender = CurrentUser.get_username()
        receiver = self.current_friend
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        message = mb.build_send_file_request(sender, receiver, file_name, file_size)
        self.parent.connection.send_message(message)
        time.sleep(1)

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((config.host, config.file_transfer_port))
        with open(file_path, 'rb') as fp:
            while True:
                data = fp.read(config.default_chunk_size)
                if not data:
                    break
                client_socket.send(data)
        client_socket.close()

        QMessageBox.information(self, "Success", "File sent successfully.")

    def receive_file(self, file_name, sender):
        self.__change_selected_friend(self.friend_list.findItems(sender, Qt.MatchExactly)[0])

        self.display_message(f"{sender} sent you a file: {file_name}.", sender)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((config.host, config.file_transfer_port))
        file_path = os.path.dirname(__file__)
        with open(file_path + '/' + file_name, 'wb') as fp:
            while True:
                data = client_socket.recv(config.default_chunk_size)
                if not data:
                    break
                fp.write(data)
        client_socket.close()

        self.display_message(f"File received successfully.", sender)


class Config():
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config_file='./config.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)

        if os.environ.get('LOCAL') == 'True':
            self.host = self.config['Local']['host']
            self.message_port = int(self.config['Local']['message_port'])
            self.file_transfer_port = int(self.config['Local']['file_transfer_port'])
        else:
            domain_name = self.config['Remote']['domain']
            self.host = socket.gethostbyname(domain_name)
            self.message_port = int(self.config['Remote']['message_port'])
            self.file_transfer_port = int(self.config['Remote']['file_transfer_port'])
        self.heartbeat_timeout = int(self.config['Server']['heartbeat_timeout'])
        self.socket_timeout = int(self.config['Server']['socket_timeout'])
        self.file_transfer_interval = float(self.config['Server']['file_transfer_interval'])
        self.default_chunk_size = int(self.config['Server']['default_chunk_size'])


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
        if len(args) > 1:
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
    connection.send_message(login_msg)
    CurrentUser.set_username(username)
    client.show_chat_page()
    client.setWindowTitle(username)


if __name__ == '__main__':
    config = Config()
    config_logging()
    # if os.environ.get('LOCAL') == 'True':
    #     ip_address = config.host
    # else:
    #     domain_name = 'ecs.wdc.zone'
    #     ip_address = socket.gethostbyname(domain_name)
    app = QApplication(sys.argv)
    client = ChatClient(config.host, config.message_port)
    client.show()
    if os.environ.get('DEBUG') == 'True':
        debug_func(client)
    sys.exit(app.exec_())

# TODO
# Chat_Connection类中不使用response_cache，而是收到response时直接调用Client相关函数进行处理
