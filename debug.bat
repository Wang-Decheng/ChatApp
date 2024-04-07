@echo off

rem 激活 Conda 环境
call activate chat

rem 设置环境变量
set LOCAL=True

rem 启动服务器
start cmd /k python ./server/server.py

rem 等待一段时间，确保服务器已经启动
timeout /t 2 >nul

rem 启动客户端
@REM start cmd /k python ./client/client.py
start pythonw /chatapp/client.py

rem 关闭窗口前，等待用户按下任意键
pause >nul

rem 关闭 Conda 环境
call deactivate
