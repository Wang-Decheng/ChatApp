import sqlite3
import hashlib
import socket
import json
import bcrypt
from threading import Thread
import os

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
    
    def register_user(self, username, password):
        if(not self._is_valid_username(username)):
            return False, 'Invalid Username'
        if(len(password) < 1): return False, 'Invalid Password'
        self.cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        existing_user = self.cursor.fetchone()
        if existing_user:
            return False, 'Username already exists'
        
        password_hash = self._hash_password(password)
        self.cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        self.conn.commit()
        return True, 'User registered successfully'

    def login_user(self, username, password):
        if(not self._is_valid_username(username)):
            return False, 'Invalid Username'
        if(len(password) < 1): return False, 'Invalid Password'
        self.cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = self.cursor.fetchone()
        if user:
            stored_password_hash = user[1]
            if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
                return True, 'Login successful'
        else:
            return False, 'User not exist'
        return False, 'Wrong Password'

    def delete_account(self, username, password):
        if(not self._is_valid_username(username)):
            return False, 'Invalid Username'
        if(len(password) < 1): return False, 'Invalid Password'
        self.cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = self.cursor.fetchone()
        if user:
            stored_password_hash = user[1]
            if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
                self.cursor.execute('DELETE FROM users WHERE username = ?', (username,))
                self.conn.commit()
                return True, 'Account deleted successfully'
        else:
            return False, 'User not exist'
        return False, 'Wrong Password'
    
    def _hash_password(self, password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')
    
    def _is_valid_username(self, username):
        # 检查用户名长度和字符范围
        # 用户名长度3-20，以字母起始，仅允许包括可打印的ascii字符
        if len(username) < 3 or len(username) > 20:
            return False
        if not username[0].isalpha():
            return False
        # if not all(ord(char) >= 32 and ord(char) < 127 and char.isalnum() for char in username):

        if not all(ord(char) >= 32 and ord(char) < 127 for char in username):
            return False
        return True

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
    ''' 如何设置环境变量
    Linux:
        export LOCAL=True
    Windows:
        临时环境变量
            set LOCAL True
        持久环境变量
            setx LOCAL True
    '''
    if os.environ.get('LOCAL') == 'True':
        ip_address = '127.0.0.1'
    else:
        ip_address = '172.31.238.212'
    server = Server(ip_address, 9999)
    server.start()