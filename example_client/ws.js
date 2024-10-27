const WebSocket = require("ws");

const ws = new WebSocket("ws://localhost:8080/");

ws.on("open", function open() {
  ws.send("Hello from client");
});

ws.on("error", function (error) {
  console.log(error);
});

ws.on("message", function (data) {
  console.log(`Received: ${data.toString()}`);
});
