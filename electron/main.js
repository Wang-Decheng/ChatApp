const { app, BrowserWindow, ipcMain, dialog } = require("electron");
//const path = require("node:path");
const {MessageBuilder, Utils} = require("./utils");
const net = require('net');

// 登录窗口
const createLoginWindow = () => {
  // Create the browser window.
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  });

  // 加载 index.html
  mainWindow.loadFile("login.html");

  // 打开开发工具
  mainWindow.webContents.openDevTools()
};

// 这段程序将会在 Electron 结束初始化和创建浏览器窗口的时候调用,部分 API 在 ready 事件触发后才能使用。
app.whenReady().then(() => {
  createLoginWindow();

  app.on("activate", () => {
    // 在 macOS 系统内, 如果没有已开启的应用窗口,点击托盘图标时通常会重新创建一个新窗口
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });

  //监听渲染进程的register事件
  ipcMain.on("register", (event, data) => {
    const { username, password } = data;
    // 将username和password封装成json
    const registerRequest = MessageBuilder.build_register_request(username, password);
    const registerRequestJson = JSON.stringify(registerRequest);
    console.log('registerRequestJson:', registerRequestJson);
    // 发送至服务器
    const serverHost = '127.0.0.1';
    const serverPort = 9999; // 指定服务器的端口号
    const client = new net.Socket();

    client.connect(serverPort, serverHost, () => {
      client.write(registerRequestJson);
    });

    client.on('data', (data) => {
      console.log('Received data from server: ' + data);
      
      try {
        // 解析 JSON 数据
        const jsonData = JSON.parse(data);
        console.log('Received JSON data:', jsonData);
        if (jsonData.success === true){
          dialog.showMessageBox({
            type: 'info',
            message: jsonData.message,
            buttons: ['确定']
          });
        } else {
          dialog.showMessageBox({
            type: 'info',
            message: jsonData.message,
            buttons: ['确定']
          });
        }
        
      } catch (error) {
        console.error('Error parsing JSON:', error);
        dialog.showMessageBox({
          type: 'error',
          message: jsonData.message,
          buttons: ['确定']
        });
      }

      //client.destroy();
    })
    
    client.on('close', () => {
      console.log('Connection to server closed');
    });
  });

  ipcMain.on("login", (event, data) => {
    const { username, password } = data;
    // 将username和password封装成json
    const loginRequest = MessageBuilder.build_login_request(username, password);
    const loginRequestJson = JSON.stringify(loginRequest);
    // 发送至服务器
    const serverHost = '127.0.0.1';
    const serverPort = 9999; // 指定服务器的端口号
    const client = new net.Socket();

    client.connect(serverPort, serverHost, () => {
      client.write(loginRequestJson);
    });

    client.on('data', (data) => {
      console.log('Received data from server: ' + data);
      
      try {
        // 解析 JSON 数据
        const jsonData = JSON.parse(data);
        console.log('Received JSON data:', jsonData);
        if (jsonData.success === true){
          dialog.showMessageBox({
            type: 'info',
            message: jsonData.message,
            buttons: ['确定']
          });
        } else {
          dialog.showMessageBox({
            type: 'info',
            message: jsonData.message,
            buttons: ['确定']
          });
        }
        
      } catch (error) {
        console.error('Error parsing JSON:', error);
        dialog.showMessageBox({
          type: 'error',
          message: jsonData.message,
          buttons: ['确定']
        });
      }

      //client.destroy();
    })
    
    client.on('close', () => {
      console.log('Connection to server closed');
    });
  });

});

// 除了 macOS 外，当所有窗口都被关闭的时候退出程序。 因此, 通常对应用程序和它们的菜单栏来说应该时刻保持激活状态,直到用户使用 Cmd + Q 明确退出
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
