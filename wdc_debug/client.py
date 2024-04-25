import sys
import socket
import json
import os
import threading
import time
from datetime import datetime

sys.path.append(".")
from utils import MessageBuilder as mb

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
    def __init__(self, host, port, heartbeat_interval = 10, timeout = 30):
        self.host = host
        self.port = port
        self.server_socket = None
        self.heartbeat_interval = heartbeat_interval
        self.timeout = timeout
        self.lock = threading.Lock()
        self.response_cache = None
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
                message_json = self.server_socket.recv(1024).decode('utf-8')
                print(f"Received message: {message_json}")
                message = json.loads(message_json)
                last_heartbeat_time = datetime.now()
                message_type = message.get('type')
                if message_type == 'heartbeat':
                    print("Received heartbeat from server")
                elif message_type == 'response':
                    self.response_cache = message
                else:
                    self.handle_message(message)
            except socket.timeout:
                print("Socket timeout")
                if (datetime.now() - last_heartbeat_time).total_seconds() > self.timeout:
                    print("Server timeout")
                self.disconnect()
            except json.JSONDecodeError:
                print("Error decoding JSON message")
            except KeyError as e:
                print(f"Missing key in message: {e}")

    def handle_message(self, message):
        if message['type'] == 'personal_message':
            sender = message['sender']
            content = message['content']
            timestamp = message['timestamp']
            timestamp_datetime = datetime.fromtimestamp(timestamp)
            formatted_timestamp = timestamp_datetime.strftime("%m-%d %H:%M")
            print(f"[{formatted_timestamp}]{sender}->You:{content}")
    
    def send_message(self, message):
        if not self.server_socket:
            self.start_connect()
        with self.lock:
            try:
                message_json = json.dumps(message)
                print(f"Sending message: {message_json}")
                self.server_socket.send(message_json.encode('utf-8'))
            except Exception as e:
                print(str(e))
                self.disconnect()
    
    def send_heartbeat(self):
        while self.server_socket is not None:
            try:
                username = CurrentUser.get_username()
                if username is not None:
                    message = mb.build_heartbeat(username)
                    self.send_message(message)
            except Exception as e:
                print(f"Error sending heartbeat:{str(e)}")
            time.sleep(self.heartbeat_interval)
    
    def get_response(self, request_timestamp, timelimit = 1):
        start_time = time.time()
        while(self.response_cache is None or self.response_cache['timestamp'] < request_timestamp):
            if(time.time() - start_time > timelimit): break
        if self.response_cache['timestamp'] == request_timestamp:
            return self.response_cache
        else: return False, 'No Response'
    
    def register_user(self, username, password):
        if not username.strip() or not password.strip():
            print("Error:Username and password cannot be blank.")
            return
        message = mb.build_register_request(username, password)
        timestamp = message['timestamp']
        self.connection.send_message(message)
        response = self.get_response(timestamp)

    def login_user(self, username, password):
        message = mb.build_login_request(username, password)
        timestamp = message['timestamp']
        self.send_message(message)
        response = self.get_response(timestamp)
        if self.show_response(response):
            CurrentUser.set_username(username)

    def delete_account(self):
        raise NotImplementedError('Delete account not implemented yet.')
                
    def send_chat_message(self, message, reciver):
        username = CurrentUser.get_username()
        if username != reciver:
            content = self.message_entry.toPlainText()
            message = mb.build_send_personal_message_request(username, reciver, content)
            timestamp = message['timestamp']
            self.parent.connection.send_message(message)
            response = self.parent.get_response(timestamp)
        else: response = {'success':False, 'message': 'Can not send to yourself'}
        self.parent.show_response(response)
    def show_response(self, response):
        success = 'sccess' if response['success']  else 'failure'
        print(f"[Response]{success}: {response['message']}")
        return response['success']
    
    def send_file(self, sender, reciver, file_path):
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        message = mb.build_send_file_request(sender, reciver, file_name, file_size)
        self.send_message(message)
        time.sleep(0.3)
        if file_transfer_client.send_file(file_path):
            print(f"File {file_name} sent successfully.")

def debug_login_as_test(connection, num):
    username = 'test' + str(num)
    password = '123'
    message = mb.build_register_request(username, password)
    connection.send_message(message)
    time.sleep(0.3)
    response = connection.get_response(message['timestamp'])
    connection.show_response(response)
    message = mb.build_login_request(username, password)
    connection.send_message(message)
    time.sleep(0.3)
    response = connection.get_response(message['timestamp'])
    connection.show_response(response)
    CurrentUser.set_username(username)

def debug_add_wdc(connection):
    username = CurrentUser.get_username()
    friend = 'wdc'
    message = mb.build_add_friend_request(username, friend)
    connection.send_message(message)
    response = connection.get_response(message['timestamp'])
    connection.show_response(response)

def debug_get_friends():
    username = CurrentUser.get_username()
    message = mb.build_get_friends_request(username)
    connection.send_message(message)
    response = connection.get_response(message['timestamp'])
    connection.show_response(response)
    print(response['data'])

class FileTransferClient:

    def __init__(self, host, port):
        self.port = port
        self.host = host

    def send_file(self, file_path, chunk_size = 1024):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                client_socket.send(data)
        client_socket.close()
        return True

def debug_send_file():
    username = CurrentUser.get_username()
    reciver = 'wdc'
    file_path = './wdc_debug/large_file.bin'
    # file_path = './wdc_debug/test.txt'
    connection.send_file(username, reciver, file_path)


if __name__ == '__main__':
    ip_address = '127.0.0.1'
    connection = ChatConnection(ip_address, 9999)
    file_transfer_client = FileTransferClient(ip_address, 9998)
    connection.start_connect()
    debug_login_as_test(connection, sys.argv[1])
    debug_send_file()