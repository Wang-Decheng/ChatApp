import socket
import json
import threading
import os
from datetime import datetime
import logging
import sys
import time
import configparser

sys.path.append(".")
from utils import MessageBuilder as mb
import user_manager as usermanager

class Manager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        self.file_transfer_server = FileTransferServer(self)
        self.user_manager = usermanager.UserManager()
        self.messagehandler = MessageHandler(manager_instance=self)
        self.message_server = MessageServer(manager_instance=self)
        self.message_server.start()

class MessageServer:
    def __init__(self, manager_instance):
        config = Config()
        self.host = config.host
        self.port = config.message_port
        self.timeout = config.heartbeat_timeout
        self.socket_timeout = config.socket_timeout
        self.manager_instace = manager_instance
        self.user_manager = manager_instance.user_manager
        self.messagehandler = manager_instance.messagehandler

    def handle_client(self, client_socket, client_address):
        client_socket.settimeout(self.socket_timeout)
        last_heartbeat_time = datetime.now()
        username = None
        while True:
            try:
                message_json = client_socket.recv(1024).decode('utf-8')
                logging.debug("server receive message:" + message_json)
                message = json.loads(message_json)
                last_heartbeat_time = datetime.now()
                type = message['type']
                if type == 'heartbeat':
                    MessageServer.send_message(client_socket, mb.build_heartbeat('server'))
                    if username is None:
                        username = message['who']
                        self.user_manager.set_online(username, client_socket)
                    elif username != message['who']:
                        self.user_manager.set_offline(username)
                        username = message['who']
                        self.user_manager.set_online(username, client_socket)
                else: self.messagehandler.handle_message(message, client_socket)
            except json.JSONDecodeError as e:
                logging.error(str(e))
                client_socket.close()
                break
            except socket.timeout:
                logging.debug("socket timeout")
                if (datetime.now() - last_heartbeat_time).total_seconds() > self.timeout:
                    logging.info(f"Connection with {client_address} is closed.")
                    if username: self.user_manager.set_offline(username)
                    client_socket.close()
            except ConnectionResetError:
                logging.info(f"Connection with {client_address} is closed.")
                if username: self.user_manager.set_offline(username)
                client_socket.close()
                break
            except socket.error:
                logging.info(f"Connection with {client_address} is closed.")
                client_socket.close()
                break

    @staticmethod
    def send_message(client_socket, message):
        if message is None:
            return
        message_json = json.dumps(message)
        logging.debug("Send message:" + message_json)
        return client_socket.send(message_json.encode('utf-8'))

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        logging.info(f"Server started on {self.host}:{self.port}")

        while True:
            client_socket, client_address = server_socket.accept()
            logging.info(f"Client connected from {client_address[0]}:{client_address[1]}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
            client_handler.start()
        
class MessageHandler:

    def __init__(self, manager_instance):
        self.manager_instance = manager_instance
        self.user_manager = self.manager_instance.user_manager
        self.file_transfer_server = self.manager_instance.file_transfer_server
        config = Config()
        self.file_transfer_interval =  config.file_transfer_interval

    def handle_message(self, message, client_socket):
        type = message['type']
        response = None
        if type == 'request':
            action = message['action']
            match action:
                case 'login':
                    response = self.handle_login(message, client_socket)
                case 'logout':
                    response = self.handle_logout(message)
                case 'register':
                    response = self.handle_register(message)
                case 'delete_account':
                    response = self.handle_delete_account(message)
                case 'send_personal_message':
                    response = self.handle_send_personal_message(message)
                case 'add_friend':
                    response = self.handle_add_friend(message)
                case 'get_friends':
                    response = self.handle_get_friends(message)
                case 'delete_friend':
                    response = self.handle_delete_friend(message)
                case 'file_transfer':
                    response = self.handle_file_transfer(message)
        if response:
            MessageServer.send_message(client_socket, response)

    def handle_login(self, message, client_socket):
        request_data = message['request_data']
        request_timestamp = message['timestamp']
        username = request_data.get('username')
        password = request_data.get('password')
        success, response_text = self.user_manager.login_user(username, password)
        if success:
            self.user_manager.set_online(username, client_socket)
        logging.debug(self.user_manager.is_online(username))
        return mb.build_response(success, response_text, request_timestamp)
    

    def handle_logout(self, message):
        request_data = message['request_data']
        request_timestamp = message['timestamp']
        username = request_data.get('username')
        if self.user_manager.is_online(username):
            self.user_manager.set_offline(username)
        return mb.build_response(True, 'logout success', request_timestamp)

    def handle_register(self, message):
        request_data = message['request_data']
        request_timestamp = message['timestamp']
        username = request_data.get('username')
        password = request_data.get('password')
        success, response_text = self.user_manager.register_user(username, password)
        return mb.build_response(success, response_text, request_timestamp)

    def handle_delete_account(self, message):
        request_data = message['request_data']
        request_timestamp = message['timestamp']
        username = request_data.get('username')
        password = request_data.get('password')
        success, response_text = self.user_manager.delete_account(username, password)
        return mb.build_response(success, response_text, request_timestamp)

    def handle_send_personal_message(self, message):
        request_data = message['request_data']
        request_timestamp = message['timestamp']
        receiver = request_data.get('receiver')
        if self.user_manager.is_online(receiver):
            receiver_client = self.user_manager.get_socket(receiver)
            success = MessageServer.send_message(receiver_client, request_data)
            if success: response_text = 'send success'
        else:
            success, response_text = False, 'Receiver is not Online'
        return mb.build_response(success, response_text, request_timestamp)
    
    def handle_add_friend(self, message):
        request_data = message['request_data']
        request_timestamp = message['timestamp']
        username = request_data.get('username')
        friend = request_data.get('friend')
        success, response_text = self.user_manager.add_friend(username, friend)
        return mb.build_response(success, response_text, request_timestamp)
    
    def handle_get_friends(self, message):
        request_data = message['request_data']
        request_timestamp = message['timestamp']
        username = request_data.get('username')
        success, response_text, response_data = self.user_manager.get_friends(username)
        user_status_dict = {}
        for user in response_data:
            status = self.user_manager.is_online(user)
            user_status_dict[user] = status
        return mb.build_response(success, response_text, request_timestamp, user_status_dict)
    
    def handle_delete_friend(self, message):
        request_data = message['request_data']
        request_timestamp = message['timestamp']
        username = request_data.get('username')
        frient = request_data.get('frient')
        success, response_text = self.user_manager.delete_friend(username, frient)
        return mb.build_response(success, response_text, request_timestamp)

    def handle_file_transfer(self, message):
        request_data = message['request_data']
        request_timestamp = message['timestamp']
        receiver = request_data.get('receiver')
        if not self.user_manager.is_online(receiver):
            return mb.build_response(False, 'Receiver is not Online', request_timestamp)
        file_name = request_data.get('file_name')
        file_size = request_data.get('file_size')
        chunk_size = request_data.get('chunk_size')
        destination_folder = f'server_files/{receiver}'
        if not os.path.exists(destination_folder):
            os.makedirs(destination_folder)
        file_path = os.path.join(destination_folder, file_name)
        success = self.file_transfer_server.receive_file(file_path, chunk_size)
        if not success:
            return mb.build_response(False, 'File transfer failed', request_timestamp)
        receiver_client = self.user_manager.get_socket(receiver)
        message = mb.build_send_file_request(request_data['sender'], receiver, file_name, file_size, request_data['timestamp'], chunk_size)
        self.manager_instance.message_server.send_message(receiver_client, message)
        time.sleep(0.3)
        success = self.file_transfer_server.send_file(file_path, chunk_size)
        if success:
            response_text = 'File transfer success'
        else:
            response_text = 'File transfer failed'
        return mb.build_response(success, response_text, request_timestamp)

class FileTransferServer:
    def __init__(self, manager_instance):
        configparser = Config()
        self.host = configparser.host
        self.port = configparser.file_transfer_port
        self.manager_instance = manager_instance

    def receive_file(self, file_path ,chunk_size):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        client_socket, client_address = self.socket.accept()
        logging.info(f"Client connected from {client_address[0]}:{client_address[1]}")
        with open(file_path, 'wb') as f:
            while True:
                data = client_socket.recv(chunk_size)
                if not data:
                    break
                f.write(data)
        client_socket.close()
        self.socket.close()
        logging.info(f"File {file_path} received")
        return True
    
    def send_file(self, file_path, chunk_size = 1024):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        client_socket, client_address = self.socket.accept()
        logging.info(f"Client connected from {client_address[0]}:{client_address[1]}")
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                client_socket.send(data)
        client_socket.close()
        logging.info(f"File {file_path} sent")
        return True

class Config:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    def __init__(self, config_file='./server/config.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        if os.environ.get('LOCAL'):
            self.host = self.config['Local']['host']
            self.message_port = int(self.config['Local']['message_port'])
            self.file_transfer_port = int(self.config['Local']['file_transfer_port'])
        else:
            self.host = self.config['Remote']['host']
            self.message_port = int(self.config['Remote']['message_port'])
            self.file_transfer_port = int(self.config['Remote']['file_transfer_port'])
        self.heartbeat_timeout = int(self.config['Server']['heartbeat_timeout'])
        self.socket_timeout = int(self.config['Server']['socket_timeout'])
        self.file_transfer_interval = float(self.config['Server']['file_transfer_interval'])

def config_logging(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(format)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        file_handler = logging.FileHandler('server.log')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

if __name__ == '__main__':
    config_logging()
    Manager()