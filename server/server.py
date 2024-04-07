import sqlite3
import socket
import json
import sys
import bcrypt
from threading import Thread
import os

sys.path.append(".")
from utils import Utils

class UserManager:
    # 单例模式
    _instance = None
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self.conn = sqlite3.connect('users.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')
        self.conn.commit()
    
    def _validate_credentials(self, username, password, register = False):
        success, message = Utils.is_valid_username_then_password(username, password)
        if success:
            self.cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = self.cursor.fetchone()
            if user is None:
                if not register:
                    success, message = False, 'USER_NOT_EXIST'
            elif not register:
                stored_password_hash = user[1]
                if not bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
                    success, message = False, 'WRONG_PASSWORD'
            else:
                success, message = False, 'USER_HAS_EXIST'
        return success, message

    def register_user(self, username, password):
        success, message  = self._validate_credentials(username, password, True)
        message = Utils.sys_msg_to_user_msg(message)
        if success:
            password_hash = Utils.hash_password(password)
            self.cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
            self.conn.commit()
            message = 'User registered successfully'
        return success, message 

    def login_user(self, username, password):
        success, message = self._validate_credentials(username, password)
        message = Utils.sys_msg_to_user_msg(message) 
        if success:
            message = 'Login successful!'
            #此处为登录逻辑
        return success, message

    def delete_account(self, username, password):
        success, message = self._validate_credentials(username, password)
        message = Utils.sys_msg_to_user_msg(message)
        if success:
            self.cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            self.conn.commit()
            message = 'Account deleted successfully'
        return success, message
    
    def close_connection(self):
        self.conn.close()

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.user_manager = UserManager()
    
    def handle_client(self, client_socket):
        request = client_socket.recv(1024).decode('utf-8')
        request_data = json.loads(request)
        username = request_data.get('username')
        password = request_data.get('password')
        response = {}
        if request_data.get('action') == 'register':
            success, message = self.user_manager.register_user(username, password)
            response['success'] = success
            response['message'] = message
        elif request_data.get('action') == 'login':
            success, message = self.user_manager.login_user(username, password)
            response['success'] = success
            response['message'] = message
        elif request_data.get('action') == 'delete_account':
            success, message = self.user_manager.delete_account(username, password)
            response['success'] = success
            response['message'] = message
        client_socket.send(json.dumps(response).encode('utf-8'))
        client_socket.close()

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Client connected from {client_address[0]}:{client_address[1]}")
            client_handler = Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()

if __name__ == '__main__':
    if os.environ.get('LOCAL') == 'True':
        ip_address = '127.0.0.1'
    else:
        ip_address = '172.31.238.212'
    print(ip_address)
    server = Server(ip_address, 9999)
    server.start()