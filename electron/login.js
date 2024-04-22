const { ipcRenderer } = require("electron");

document.addEventListener("DOMContentLoaded", () => {
  console.log("1111")
  document.getElementById("loginBtn").addEventListener("click", () => {
    console.log("loginBtn clicked");
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    ipcRenderer.send("login", { username, password });
  });
});

// document.getElementById("loginBtn").addEventListener("click", () => {
//   // 获取账号和密码
//   console.log("loginBtn clicked");
//   const username = document.getElementById("username").value;
//   const password = document.getElementById("password").value;

//   // 发送账号和密码到主进程
//   ipcRendererLogin.send("login", { username, password });
// });
