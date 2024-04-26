import bcrypt
import time


class Utils:

    @staticmethod
    def is_valid_username(username: str):
        '''用户名合法性检测：
        检查用户名长度和字符范围
        用户名长度3-20，以字母起始，仅允许包括可打印的ascii字符
        返回布尔值以及一个报错信息,可以根据这些信息给出对应的处理或者反馈
        '''
        minlen = 3
        maxlen = 20
        if len(username) < minlen:
            return False, 'Username is too short'
        elif len(username) > maxlen:
            return False, 'Username is too long'

        if not username[0].isalpha():
            return False, 'The first character of username should be a letter'

        # 要求用户名必须为可打印ASCII字符
        if not all(ord(char) >= 32 and ord(char) < 127 for char in username):
            return False, 'Username has invald characters'
        return True, 'OK'

    @staticmethod
    def hash_password(password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')

    @staticmethod
    def is_valid_password(password):
        minlen = 3
        maxlen = 16
        if len(password) < minlen:
            return False, 'Password is too short'
        elif len(password) > maxlen:
            return False, 'Password is too long'

        if not password.isalnum():
            return False, 'Password contains illegal characters'

        return True, 'OK'

    @staticmethod
    def is_valid_username_then_password(username, password):
        success, message = Utils.is_valid_username(username)
        if success:
            success, message = Utils.is_valid_password(password)
        return success, message


class MessageBuilder:

    # 生成响应信息
    @staticmethod
    def build_response(success, message, request_timestamp, data=None):
        message_data = {
            'type': 'response',
            'timestamp': request_timestamp,
            'success': success,
            'message': message,
            'data': data
        }
        return message_data
    def build_get_friends_response_data(friends):
        response_data = {
            'type': 'friends',
            'friends': friends
        }
        return response_data
    # 生成心跳包
    @staticmethod
    def build_heartbeat(who):
        message_data = {'type': 'heartbeat', 'who': who, 'timestamp': time.time()}
        return message_data

    # region 生成请求消息
    # 根据请求内容生成请求
    @staticmethod
    def build_request(action, request_data, timestamp=time.time()):
        message_data = {
            'type': 'request',
            'action': action,
            'timestamp': timestamp,
            'request_data': request_data
        }
        return message_data

    # 根据请求类型的不同生成不同的请求内容对象，然后生成请求信息，下同
    @staticmethod
    def build_login_request(username, password):
        request_data = {'username': username, 'password': password}
        return MessageBuilder.build_request('login', request_data)
    
    def build_logout_request(username):
        request_data = {'username': username}
        return MessageBuilder.build_request('logout', request_data)

    @staticmethod
    def build_register_request(username, password):
        request_data = {'username': username, 'password': password}
        return MessageBuilder.build_request('register', request_data)

    @staticmethod
    def build_delete_account_request(username, password):
        request_data = {'username': username, 'password': password}
        return MessageBuilder.build_request('delete_account', request_data)
    
    @staticmethod
    def build_add_friend_request(username, friend):
        request_data = {'username': username,'friend': friend}
        return MessageBuilder.build_request('add_friend', request_data)
    
    @staticmethod
    def build_get_friends_request(username):
        request_data = {'username': username}
        return MessageBuilder.build_request('get_friends', request_data)
    
    @staticmethod
    def build_remove_friend_request(username, friend):
        request_data = {'username': username,'friend': friend}
        return MessageBuilder.build_request('remove_friend', request_data)

    @staticmethod
    def build_send_personal_message_request(sender, receiver, content):
        message_data = {
            'type': 'personal_message',
            'sender': sender,
            'receiver': receiver,
            'content': content,
            'timestamp': time.time()
        }
        return MessageBuilder.build_request('send_personal_message', message_data)

    @staticmethod
    def build_send_group_message_request(sender, group, content):
        message_data = {
            'type': 'group_message',
            'sender': sender,
            'group': group,
            'content': content,
            'timestamp': time.time()
        }
        return MessageBuilder.build_request('send_group_messager', message_data)

    def build_send_file_request(sender, receiver, file_name, file_size, timestamp = time.time(), chunk_size = 1024):
        request_data = {
            'sender': sender,
            'receiver': receiver,
            'file_name': file_name,
            'file_size': file_size,
            'chunk_size': chunk_size,
            'timestamp': timestamp
        }
        return MessageBuilder.build_request('file_transfer', request_data)
    
    # endregion
