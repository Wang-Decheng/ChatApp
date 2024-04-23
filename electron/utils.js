const bcrypt = require('bcrypt');

class Utils {
    static is_valid_username(username) {
        const minlen = 3;
        const maxlen = 20;
        if (username.length < minlen) {
            return [false, 'Username is too short'];
        } else if (username.length > maxlen) {
            return [false, 'Username is too long'];
        }

        if (!username[0].match(/[a-zA-Z]/)) {
            return [false, 'The first character of username should be a letter'];
        }

        if (![...username].every(char => char.charCodeAt(0) >= 32 && char.charCodeAt(0) < 127)) {
            return [false, 'Username has invalid characters'];
        }
        return [true, 'OK'];
    }

    static hash_password(password) {
        const salt = bcrypt.genSaltSync();
        const hashed_password = bcrypt.hashSync(password, salt);
        return hashed_password;
    }

    static is_valid_password(password) {
        const minlen = 3;
        const maxlen = 16;
        if (password.length < minlen) {
            return [false, 'Password is too short'];
        } else if (password.length > maxlen) {
            return [false, 'Password is too long'];
        }

        if (!password.match(/^[a-zA-Z0-9]+$/)) {
            return [false, 'Password contains illegal characters'];
        }
        return [true, 'OK'];
    }

    static is_valid_username_then_password(username, password) {
        let [success, message] = Utils.is_valid_username(username);
        if (success) {
            [success, message] = Utils.is_valid_password(password);
        }
        return [success, message];
    }
}

class MessageBuilder {
    static build_response(success, message, request_timestamp) {
        return {
            type: 'response',
            timestamp: request_timestamp,
            success: success,
            message: message
        };
    }

    static build_heartbeat(who) {
        return {
            type: 'heartbeat',
            who: who,
            timestamp: Date.now()
        };
    }

    static __build_request(action, request_data) {
        return {
            type: 'request',
            action: action,
            timestamp: Date.now(),
            request_data: request_data
        };
    }

    static build_login_request(username, password) {
        const request_data = { username: username, password: password };
        return MessageBuilder.__build_request('login', request_data);
    }

    static build_register_request(username, password) {
        const request_data = { username: username, password: password };
        return MessageBuilder.__build_request('register', request_data);
    }

    static build_delete_request(username, password) {
        const request_data = { username: username, password: password };
        return MessageBuilder.__build_request('delete', request_data);
    }

    static build_get_friends_list_request(username) { //获取好友列表
        const request_data = { username: username };
        return MessageBuilder.__buildRequest('get_friends', request_data);
    }

    static build_send_personal_message_request(sender, receiver, content) {
        return MessageBuilder.__build_request('send_personal_message', {
            type: 'personal_message',
            sender: sender,
            receiver: receiver,
            content: content,
            timestamp: Date.now()
        });
    }

    static build_send_group_message_request(sender, group, content) {
        return MessageBuilder.__build_request('send_group_messager', {
            type: 'group_message',
            sender: sender,
            group: group,
            content: content,
            timestamp: Date.now()
        });
    }
}

module.exports = {
    Utils: Utils,
    MessageBuilder: MessageBuilder
};