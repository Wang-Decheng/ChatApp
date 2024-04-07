import bcrypt

class Utils:

    _instance = None    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    # 系统错误信息到用户错误信息反馈的词典
    # 此词典存在的原因是对响应消息进行统一管理，避免出现响应相同相同却不一致的消息等冗余或错误信息，避免响应消息混乱
    # 对于一对多的响应消息如 OK,不统一处理
    msg_dict = {
        "TOO_SHORT_USERNAME": "Username is too short",
        "TOO_LONG_USERNAME": "Username is too long",
        "HEAD_NOT_NUM": "The first character of username should be a letter",
        "INCLUDE_NOT_ASCII_CHAR" : "Username has invald characters",
        "TOO_SHORT_PASSWORD": "Password is too short",
        "TOO_LONG_PASSWORD": "Password is too long",
        "USER_NOT_EXIST": "User is not exist",
        "WRONG_PASSWORD": "The password is wrong",
        "USER_HAS_EXIST": "Username already exists"
    }

    def is_valid_username(username):
        '''用户名合法性检测：
        检查用户名长度和字符范围
        用户名长度3-20，以字母起始，仅允许包括可打印的ascii字符
        返回布尔值以及一个报错信息,可以根据这些信息给出对应的处理或者反馈
        '''
        minlen = 3
        maxlen = 20
        if len(username) < minlen:
            return False, 'TOO_SHORT_USERNAME'
        elif len(username) > maxlen:
            return False, 'TOO_LONG_USERNAME'
        if not username[0].isalpha():
            return False, 'HEAD_NOT_NUM'
        if not all(ord(char) >= 32 and ord(char) < 127 for char in username):
            return False, 'INCLUDE_NOT_ASCII_CHAR'
        return True, 'OK'
    
    def hash_password(password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')
    
    def is_valid_password(password):
        minlen = 3
        maxlen = 16
        if len(password) < minlen:
            return False, 'TOO_SHORT_PASSWORD'
        elif len(password) > maxlen:
            return False, 'TOO_LONG_PASSWORD'
        return True, 'OK'
    
    def is_valid_username_then_password(username, password):
        success, message = Utils.is_valid_username(username)
        if success:
            success, message = Utils.is_valid_password(password)
        return success, message
    
    def sys_msg_to_user_msg(message):
        if message in Utils.msg_dict:
            return Utils.msg_dict[message]
        else:
            print("undefined message: " + message)
            return message
