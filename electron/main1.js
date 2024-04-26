const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const { MessageBuilder, Utils } = require("./utils");
const net = require("net");
const { log } = require("console");
const { create } = require("domain");

const serverHost = "127.0.0.1"; // 指定服务器的 IP 地址
const serverPort = 9999; // 指定服务器的端口号
let timeStampBuffer = {};
const requestType = {
    REGISTER: "register",
    LOGIN: "login",
    GETFRIENDSLIST: "getFriendsList"
}
var id;
var friendsList;

function sleep(time) {
    var timeStamp = new Date().getTime();
    var endTime = timeStamp + time;
    while (true) {
        if (new Date().getTime() > endTime) {
            return;
        }
    }
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

const createAddFriendWindow = () => {
    const mainWindow = new BrowserWindow({
        width: 400,
        height: 150,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
        },
    });

    mainWindow.loadFile("addFriendWin.html");
    //mainWindow.webContents.openDevTools();
};

const createDeleteFriendWindow = () => {
    const mainWindow = new BrowserWindow({
        width: 400,
        height: 150,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
        },
    });

    mainWindow.loadFile("deleteFriendWin.html");
    //mainWindow.webContents.openDevTools();
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
    id = username;

    const loginRequest = MessageBuilder.build_login_request(username, password);
    const loginRequestJson = JSON.stringify(loginRequest);
    timeStampBuffer[loginRequest.timestamp] = requestType.LOGIN;

    sleep(1000); //间隔一秒，以获得不同的时间戳

    const friendsListRequest = MessageBuilder.build_get_friends_list_request(username);
    const friendsListRequestJson = JSON.stringify(friendsListRequest);
    timeStampBuffer[friendsListRequest.timestamp] = requestType.GETFRIENDSLIST;

    const client = new net.Socket();

    client.connect(serverPort, serverHost, () => {
        client.write(loginRequestJson);
        sleep(1000); //间隔几秒，防止粘包
        client.write(friendsListRequestJson);
        setInterval(() => {
            client.write(friendsListRequestJson);
        }, 1000);  //每隔1秒发送一次获取好友列表请求
    });

    client.on("data", (data) => {
        const jsonData = JSON.parse(data);
        console.log("Received JSON data:", jsonData);
        if (jsonData.timestamp in timeStampBuffer) {
            const responseType = timeStampBuffer[jsonData.timestamp];
            console.log(responseType);
            if (responseType === requestType.LOGIN) {
                if (jsonData.success === true) {
                    const friendsWindow = createFriendsWindow();
                } else {
                    dialog.showMessageBox({
                        type: "info",
                        message: "服务器初次连接异常",
                        buttons: ["确定"],
                    });
                }
            } else if (responseType === requestType.GETFRIENDSLIST) {
                friendsList = jsonData.data;
                console.log(friendsList);
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

const addfriend = (event, data) => {
    createAddFriendWindow();
};

const getFriendNameAndAdd = (event, data) => {
    const friendName = data;
    client = new net.Socket();
    const addFriendRequest = MessageBuilder.build_add_friend_request(id, friendName);
    const addFriendRequestJson = JSON.stringify(addFriendRequest);
    console.log(addFriendRequestJson);
    client.connect(serverPort, serverHost, () => {
        client.write(addFriendRequestJson);
    });
    client.on("data", (data) => {
        const jsonData = JSON.parse(data);
        console.log("Received JSON data:", jsonData);
        if (jsonData.success === true) {
            dialog.showMessageBox({
                type: "info",
                message: jsonData.message,
                buttons: ["确定"],
            });
        }
    });
}

const deleteFriend = (event, data) => {
    createDeleteFriendWindow();
}

const getFriendNameAndDelete = (event, data) => {
    const friendName = data;
    client = new net.Socket();
    const deleteFriendRequest = MessageBuilder.build_remove_friend_request(id, friendName);
    const deleteFriendRequestJson = JSON.stringify(deleteFriendRequest);
    console.log(deleteFriendRequestJson);
    client.connect(serverPort, serverHost, () => {
        client.write(deleteFriendRequestJson);
    });
    client.on("data", (data) => {
        const jsonData = JSON.parse(data);
        console.log("Received JSON data:", jsonData);
        if (jsonData.success === true) {
            dialog.showMessageBox({
                type: "info",
                message: jsonData.message,
                buttons: ["确定"],
            });
        }
    });
}

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
        return friendsWindow;

    } else {
        dialog.showMessageBox({
            type: "info",
            message: "服务器连接异常",
            buttons: ["确定"],
        });
        return null;
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

    ipcMain.on("addFriend", addfriend);

    ipcMain.on("getFriendNameAndAdd",getFriendNameAndAdd);

    ipcMain.on("deleteFriend",deleteFriend);

    ipcMain.on("getFriendNameAndDelete",getFriendNameAndDelete);

    // 主进程创建事件   
    ipcMain.handle("getFriendsList", () => {
        return friendsList;
    });

    ipcMain.handle("getId", () => {
        return id;
    });

});

// 除了 macOS 外，当所有窗口都被关闭的时候退出程序。 因此, 通常对应用程序和它们的菜单栏来说应该时刻保持激活状态,直到用户使用 Cmd + Q 明确退出
app.on("window-all-closed", () => {
    if (process.platform !== "darwin") app.quit();
});

