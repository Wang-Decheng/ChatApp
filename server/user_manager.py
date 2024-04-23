import sys
import sqlite3
import bcrypt

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
        self.cursor.execute(
            '''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS friendship (
                username TEXT NOT NULL,
                friendname TEXT NOT NULL,
                PRIMARY KEY (username, friendname),
                FOREIGN KEY (username) REFERENCES users(username),
                FOREIGN KEY (friendname) REFERENCES users(username)
            )
        ''')
        self.conn.commit()
        self.online_users = {}

    def _validate_credentials(self, username, password, register=False):
        success, message = Utils.is_valid_username_then_password(username, password)
        if success:
            self.cursor.execute('SELECT * FROM users WHERE username = ?', (username, ))
            user = self.cursor.fetchone()
            if user is None:
                if not register:
                    success, message = False, 'User is not exist'
            elif not register:
                stored_password_hash = user[1]
                if not bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
                    success, message = False, 'The password is wrong'
            else:
                success, message = False, 'Username already exists'
        return success, message

    def register_user(self, username, password):
        success, message = self._validate_credentials(username, password, True)
        if success:
            password_hash = Utils.hash_password(password)
            self.cursor.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash)
            )
            self.conn.commit()
            message = 'User registered successfully'
        return success, message

    def login_user(self, username, password):
        success, message = self._validate_credentials(username, password)
        if success:
            message = 'Login successful!'
        return success, message

    def delete_account(self, username, password):
        success, message = self._validate_credentials(username, password)
        if success:
            self.cursor.execute('DELETE FROM users WHERE username = ?', (username, ))
            self.conn.commit()
            message = 'Account deleted successfully'
        return success, message
    
    def is_username_exist(self, username):
        self.cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = self.cursor.fetchone()
        return user is not None
    
    def get_friends(self, username):
        self.cursor.execute('SELECT friendname FROM friendship WHERE username = ?', (username,))
        friends = self.cursor.fetchall()
        return [friend[0] for friend in friends]
    
    def add_friend(self, username, friend_username):
        if not self.is_username_exist(friend_username):
            return False, 'User is not exist'
        
        # Check if the friendship already exists
        self.cursor.execute('SELECT * FROM friendship WHERE (username = ? AND friendname = ?) OR (username = ? AND friendname = ?)', (username, friend_username, friend_username, username))
        existing_friendship = self.cursor.fetchone()
        
        if existing_friendship:
            return False, 'Friendship already exists'
        
        # If friendship doesn't exist, then add the friend
        self.cursor.execute('INSERT INTO friendship (username, friendname) VALUES (?, ?)', (username, friend_username))
        self.conn.commit()
        return True, 'Friend added successfully'

    
    def remove_friend(self, username, friend_username):
        if not self.is_username_exist(friend_username):
            return False, 'User is not exist'
        self.cursor.execute('DELETE FROM friendship WHERE username = ? AND friendname = ?', (username, friend_username))
        self.conn.commit()
        return True, 'Friend removed successfully'

    
    def set_online(self, username, socket):
        self.online_users[username] = socket

    def set_offline(self, username):
        if username in self.online_users:
            del self.online_users[username]

    def is_online(self, username):
        return username in self.online_users

    def get_socket(self, username):
        return self.online_users.get(username)

    def close_connection(self):
        self.conn.close()
