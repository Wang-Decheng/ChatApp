import socket
import json
from threading import Thread
import os
from datetime import datetime
import logging
import sys
import pickle

import user_manager as usermanager

sys.path.append(".")
from utils import MessageBuilder as mb


class Server:

    def __init__(self, host, port, heartbeat_timeout=30):
        self.host = host
        self.port = port
        self.timeout = heartbeat_timeout
        self.user_manager = usermanager.UserManager()
        self.messagehandler = MessageHandler(self.user_manager)

    def handle_client(self, client_socket, client_address):
        client_socket.settimeout(15)
        last_heartbeat_time = datetime.now()
        username = None
        while True:
            try:
                # message_json = client_socket.recv(1024).decode('utf-8')
                # logging.info("server receive message:" + message_json)
                # message = json.loads(message_json)
                message_length = int.from_bytes(client_socket.recv(4), byteorder='big')
                message_bytes = client_socket.recv(message_length)
                message = pickle.loads(message_bytes)
                if message['type'] == 'request' and message['action'] == 'file_data':
                    logging.info(f"server receive message: file_data")
                else:
                    logging.info(f"server receive message: {message}")

                last_heartbeat_time = datetime.now()
                type = message['type']
                if type == 'heartbeat':
                    Server.send_message(client_socket, mb.build_heartbeat('server'))
                    if username is None:
                        username = message['who']
                        self.user_manager.set_online(username, client_socket)
                    elif username != message['who']:
                        self.user_manager.set_offline(username)
                        username = message['who']
                        self.user_manager.set_online(username, client_socket)
                else: self.messagehandler.handle_message(message, client_socket)
            except json.JSONDecodeError:
                logging.info("json decode error")
                client_socket.close()
                break
            except socket.timeout:
                logging.debug("socket timeout")
                if (datetime.now() - last_heartbeat_time).total_seconds() > self.timeout:
                    logging.info(f"Connection with {client_address} is closed.")
                    if username:
                        self.user_manager.set_offline(username)
                    client_socket.close()
            except ConnectionResetError:
                logging.info(f"Connection with {client_address} is closed.")
                if username: self.user_manager.set_offline(username)
                client_socket.close()
                break
            except socket.error:
                logging.info(f"Connection with {client_address} is closed.")
                break

    @staticmethod
    def send_message(client_socket, message):
        if message is None:  # 空消息不发送
            return
        message_bytes = pickle.dumps(message)
        client_socket.send(len(message_bytes).to_bytes(4, byteorder='big'))
        return client_socket.send(message_bytes)
        # return client_socket.send(json.dumps(message).encode('utf-8'))

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Client connected from {client_address[0]}:{client_address[1]}")
            client_handler = Thread(target=self.handle_client, args=(client_socket, client_address))
            client_handler.start()


class MessageHandler:

    def __init__(self, user_manager):
        self.user_manager = user_manager

    def handle_message(self, message, client_socket):
        type = message['type']
        response = None
        if type == 'request':
            action = message['action']
            match action:
                case 'login':
                    response = self.handle_login(message, client_socket)
                case 'register':
                    response = self.handle_register(message)
                case 'delete':
                    response = self.handle_delete_account(message)
                case 'send_personal_message':
                    response = self.handle_send_personal_message(message)
                case 'file_transfer_header':
                    response = self.handle_file_transfer_header(message)
                case 'file_data':
                    response = self.handle_file_data(message)
        if message:
            Server.send_message(client_socket, response)

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
            success = Server.send_message(receiver_client, request_data)
            if success: response_text = 'send success'
        else:
            success, response_text = False, 'Receiver is not Online'
        return mb.build_response(success, response_text, request_timestamp)

    def handle_file_transfer_header(self, message):
        request_data = message['request_data']
        request_timestamp = message['timestamp']
        receiver = request_data.get('receiver')
        if self.user_manager.is_online(receiver):
            receiver_client = self.user_manager.get_socket(receiver)
            success = Server.send_message(receiver_client, request_data)
            if success:
                response_text = 'file transfer request sent'
        else:
            success, response_text = False, 'Receiver is not Online'
        return mb.build_response(success, response_text, request_timestamp)

    def handle_file_data(self, message):
        request_data = message['request_data']
        request_timestamp = message['timestamp']
        receiver = request_data.get('receiver')
        receiver_client = self.user_manager.get_socket(receiver)
        success = Server.send_message(receiver_client, request_data)
        return None


def config_logging(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'):
    logger = logging.getLogger()
    logger.setLevel(level)
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter(format)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        file_handler = logging.FileHandler('s-debug.log')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)


if __name__ == '__main__':
    config_logging()
    if os.environ.get('LOCAL') == 'True':
        ip_address = '127.0.0.1'
    else:
        ip_address = '172.31.238.212'
    print(ip_address)
    server = Server(ip_address, 9999)
    server.start()

    # NOTE 是否可以把IP和端口号在utils定义，避免之后可能需要多处更改
