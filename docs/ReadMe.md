### 如何运行服务器端

#### Linux

1. 安装依赖

   ```shell
   pip install -r requirements.txt
   ```

2. 修改配置文件`config.ini`

   按照具体的网络配置信息

   ```ini
   [Local]
   host = 127.0.0.1
   message_port = 9999
   file_transfer_port = 9998
   
   [Remote]
   host =  172.21.136.189
   domain = ecs.wdc.zone
   message_port = 9999
   file_transfer_port = 9998
   ```

3. 在目录`ChatApp`下运行服务器文件

   ```shell
   python3 ./server/server.py
   ```

   