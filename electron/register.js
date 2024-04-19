// const { ipcRenderer} = require("electron");

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("registerBtn").addEventListener("click", () => {
    // 获取账号和密码
    console.log("registerBtn clicked");
    const username = document.getElementById("username").value; // 假设有一个文本输入框来输入用户名
    const password = document.getElementById("password").value; // 假设有一个密码输入框来输入密码
  
    // 发送账号密码到主进程
    ipcRenderer.send("register", { username, password });
  });
});

// document.getElementById("registerBtn").addEventListener("click", () => {
//   // 获取账号和密码
//   console.log("registerBtn clicked");
//   const username = document.getElementById("username").value; // 假设有一个文本输入框来输入用户名
//   const password = document.getElementById("password").value; // 假设有一个密码输入框来输入密码

//   // 发送账号和密码到主进程
//   ipcRendererRegister.send("register", { username, password });
// });
