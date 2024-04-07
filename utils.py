import bcrypt

class utils:
    def _is_valid_username(username):
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
    def _hash_password(password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')
    def _is_valid_password(passward):
        return len(passward) >= 3