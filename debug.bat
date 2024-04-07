@echo off

rem Activate Conda environment
call activate chat

rem Set environment variable
set LOCAL=True

rem Start the server
start cmd /k python ./server/server.py

rem Wait for a while to ensure the server has started
timeout /t 2 >nul

rem Start the client
rem start pythonw /chatapp/client.py
start cmd /k python ./client/client.py

rem Wait for the user to press any key before closing the window
pause >nul

rem Deactivate the Conda environment
call deactivate