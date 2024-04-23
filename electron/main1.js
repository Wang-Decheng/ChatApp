const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const { MessageBuilder, Utils } = require("./utils");
const net = require("net");

const serverHost = "127.0.0.1"; // 指定服务器的 IP 地址
const serverPort = 9999; // 指定服务器的端口号
let timeStampBuffer = {};
const requestType = {
    REGISTER: "register",
    LOGIN: "login",
}

const createLoginWindow = () => {

    const mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
        },
    });

    mainWindow.loadFile("login.html");
    mainWindow.webContents.openDevTools();
};

const createFriendsWindow = () => {
    const mainWindow = new BrowserWindow({
        width: 800,
        height: 1000,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
        },
    });

    mainWindow.loadFile("friendsWin.html");
    mainWindow.webContents.openDevTools();
};

const createChatWindow = () => {
    const mainWindow = new BrowserWindow({
        width: 800,
        height: 1000,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
        },
    });

    mainWindow.loadFile("chatWin.html");
    mainWindow.webContents.openDevTools();
};

const register = (event, data) => {
    const { username, password } = data; //数据解封装
    const registerRequest = MessageBuilder.build_register_request(
        username,
        password
    );
    const registerRequestJson = JSON.stringify(registerRequest);
    timeStampBuffer[registerRequest.timestamp] = requestType.REGISTER;

    // 发送至服务器
    const client = new net.Socket();

    client.connect(serverPort, serverHost, () => {
        client.write(registerRequestJson);
    });

    client.on("data", (data) => {
        console.log("Received data from server: " + data);

        // 解析 JSON 数据
        const jsonData = JSON.parse(data);
        console.log("Received JSON data:", jsonData);

        if (jsonData.timestamp in timeStampBuffer) {
            const responseType = timeStampBuffer[jsonData.timestamp];
            whichType(responseType, jsonData);
        }

        client.destroy();
    });

};

const login = (event, data) => {
    const { username, password } = data;

    const id = username;
    let friendslist;

    ipcMain.handle("getId", () => {
        return id;
    });

    const loginRequest = MessageBuilder.build_login_request(username, password);
    const loginRequestJson = JSON.stringify(loginRequest);
    timeStampBuffer[loginRequest.timestamp] = requestType.LOGIN;
    
    const client = new net.Socket();

    client.connect(serverPort, serverHost, () => {
        client.write(loginRequestJson);
    });

    client.on("data", (data) => {
        const jsonData = JSON.parse(data);
        console.log("Received JSON data:", jsonData);

        if (jsonData.timestamp in timeStampBuffer) {
            const responseType = timeStampBuffer[jsonData.timestamp];
            if (responseType === requestType.LOGIN) {
                getLoginResponse(jsonData);
            }
        }
        
    });


    client.on("close", () => {
        console.log("Connection to server closed");
    });
};

const chat = (event, data) => {
    createChatWindow();
};

const whichType = (responseType, jsonData) => {
    switch (responseType) {
        case requestType.REGISTER:
            return getRegisterResponse(jsonData);
        case requestType.LOGIN:
            return getLoginResponse(jsonData);
        default:
            return null;
    }
};

const getRegisterResponse = (jsonData) => {
    if (jsonData.success === true) {
        dialog.showMessageBox({
            type: "info",
            message: jsonData.message,
            buttons: ["确定"],
        });
    } else {
        dialog.showMessageBox({
            type: "info",
            message: jsonData.message,
            buttons: ["确定"],
        });
    }
};

const getLoginResponse = (jsonData) => {
    if (jsonData.success === true) {

        const friendsWindow = createFriendsWindow();
        // const friendsListRequest = MessageBuilder.build_get_friends_list_request(id);
        // const friendsListRequestJson = JSON.stringify(friendsListRequest);
        // client.write(friendsListRequestJson);

    } else {
        dialog.showMessageBox({
            type: "info",
            message: "服务器连接异常",
            buttons: ["确定"],
        });
    }
};

// 主程序，在 Electron 结束初始化和创建浏览器窗口的时候调用。
app.whenReady().then(() => {
    loginWindow = createLoginWindow();

    app.on("activate", () => {
        // 在 macOS 系统内, 如果没有已开启的应用窗口,点击托盘图标时通常会重新创建一个新窗口
        if (BrowserWindow.getAllWindows().length === 0) createLoginWindow();
    });

    //监听渲染进程的不同事件
    ipcMain.on("register", register);

    ipcMain.on("login", login);

    ipcMain.on("chatBegin", chat);
});

// 除了 macOS 外，当所有窗口都被关闭的时候退出程序。 因此, 通常对应用程序和它们的菜单栏来说应该时刻保持激活状态,直到用户使用 Cmd + Q 明确退出
app.on("window-all-closed", () => {
    if (process.platform !== "darwin") app.quit();
});

