## 服务器端 (server.py)

### 1. Manager 类

**描述：** 管理服务器端的各个组件，确保单例实例的创建和初始化。

**方法：**

- `__new__(cls, *args, **kwargs)`: 创建 Manager 类的单例实例。
- `__init__(self)`: 初始化 Manager 实例，创建 FileTransferServer、UserManager 和 MessageHandler 实例，并启动消息服务器。

### 2. MessageServer 类

**描述：** 负责处理消息传输和客户端连接。

**属性：**

- `host`: 服务器主机地址。
- `port`: 服务器消息端口。
- `timeout`: 心跳超时时间。
- `socket_timeout`: Socket 超时时间。

**方法：**

- `handle_client(self, client_socket, client_address)`: 处理客户端连接。
- `send_message(client_socket, message)`: 向客户端发送消息。
- `start(self)`: 启动消息服务器。

### 3. MessageHandler 类

**描述：** 处理收到的消息，并根据消息类型执行相应的操作。

**属性：**

- `manager_instance`: Manager 实例。
- `user_manager`: UserManager 实例。
- `file_transfer_server`: FileTransferServer 实例。
- `message_queues`: 用于存储离线消息的队列。

**方法：**

- `__init__(self, manager_instance)`: 初始化 MessageHandler 实例。
- `handle_message(self, message, client_socket)`: 处理收到的消息。
- 其他方法：处理不同类型的请求消息，如登录、登出、注册、删除账户、发送个人消息、添加好友、获取好友列表、删除好友、文件传输等。

### 4. FileTransferServer 类

**描述：** 处理文件传输相关的操作。

**属性：**

- `host`: 文件传输服务器主机地址。
- `port`: 文件传输服务器端口。

**方法：**

- `receive_file(self, file_path, chunk_size)`: 接收文件并保存到指定路径。
- `send_file(self, file_path, chunk_size=1024)`: 发送文件给客户端。

### 5. Config 类

**描述：** 加载和解析配置文件。

**属性：**

- `host`: 服务器主机地址。
- `message_port`: 消息端口。
- `file_transfer_port`: 文件传输端口。
- `heartbeat_timeout`: 心跳超时时间。
- `socket_timeout`: Socket 超时时间。
- `file_transfer_interval`: 文件传输间隔时间。
- `is_json_format`: 是否以 JSON 格式记录日志。
- `log_file`: 日志文件路径。
- `is_output_heartbeat`: 是否输出心跳信息。

**方法：**

- `__new__(cls, *args, **kwargs)`: 创建 Config 类的单例实例。
- `__init__(self, config_file='./server/config.ini')`: 初始化 Config 实例。

## 用户管理 (user_manager.py)

### 1. UserManager 类

**描述：** 管理用户账户和好友关系。

**方法：**

- `__new__(cls, *args, **kwargs)`: 创建 UserManager 类的单例实例。
- `__init__(self)`: 初始化 UserManager 实例，连接数据库并创建用户表和好友关系表。
- `register_user(self, username, password)`: 注册用户。
- `login_user(self, username, password)`: 用户登录。
- `delete_account(self, username, password)`: 删除用户账户。
- `is_username_exist(self, username)`: 检查用户名是否存在。
- `get_friends(self, username)`: 获取用户好友列表。
- `add_friend(self, username, friend_username)`: 添加好友。
- `remove_friend(self, username, friend_username)`: 删除好友。
- `set_online(self, username, socket)`: 设置用户在线状态。
- `set_offline(self, username)`: 设置用户离线状态。
- `is_online(self, username)`: 检查用户是否在线。
- `get_socket(self, username)`: 获取用户的 Socket 连接。
- `close_connection(self)`: 关闭数据库连接。

## 实用工具 (utils.py)

### 1. Utils 类

**描述：** 提供一些常用的工具函数，如验证用户名、密码，密码哈希等。

**方法：**

- `is_valid_username(username)`: 检查用户名合法性。
- `hash_password(password)`: 对密码进行哈希加密。
- `is_valid_password(password)`: 检查密码合法性。
- `is_valid_username_then_password(username, password)`: 先检查用户名，再检查密码的合法性。

### 2. MessageBuilder 类

**描述：** 构建不同类型的消息。

**方法：**

- `build_response(success, message, request_timestamp, data=None)`: 构建响应消息。
- `build_get_friends_response_data(friends)`: 构建获取好友列表的响应数据。
- `build_heartbeat(who)`: 构建心跳包消息。
- `build_request(action, request_data, timestamp=time.time())`: 构建请求消息。
- 其他方法：构建不同类型的请求消息，如登录、登出、注册、删除账户、添加好友、获取好友列表、删除好友、发送个人消息、发送群组消息、文件传输等。
