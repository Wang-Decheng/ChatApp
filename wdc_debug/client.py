import sys
import socket
import json
import os
import threading
import time
import requests
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
        if response['success']:
            message = response['message']
            print(f"success: {message}")
            return True
        else:
            message = response['message']
            print(f"error: {message}")
            return False

def debug_func(client):
    connection = client.connection
    args = sys.argv
    if len(args) >= 1:
        username = 'user' + args[1]
    else: username = 'user'
    password = '123'
    register_msg = mb.build_register_request(username, password)
    login_msg = mb.build_login_request(username, password)
    connection.send_message(register_msg)
    time.sleep(1)
    connection.send_message(login_msg)
    CurrentUser.set_username(username)
    client.show_chat_page()
    client.setWindowTitle(username)

def debug_send_add_friend_request(connection):
    username = 'test1'
    password = '123'
    friend_username = 'wdc'
    message = mb.build_register_request(username, password)
    connection.send_message(message)
    time.sleep(1)
    message = mb.build_register_request('wdc', password)
    connection.send_message(message)
    message = mb.build_login_request(username, password)
    connection.send_message(message)
    time.sleep(1)
    CurrentUser.set_username(username)
    message = mb.build_add_friend_request(username, friend_username)
    connection.send_message(message)
    time.sleep(1)
    response = connection.get_response(message['timestamp'])
    connection.show_response(response)

def debug_get_friends():
    url = 'http://127.0.0.1:5000/api/get_friends'
    params = {'username': 'test1'}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        # data = response.json()
        print(response.text)
    else:
        print("Failed to get friends. Status code:", response.status_code)

if __name__ == '__main__':
    ip_address = '127.0.0.1'
    connection = ChatConnection(ip_address, 9999)
    debug_send_add_friend_request(connection)
    debug_get_friends()
    