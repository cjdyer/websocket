# WebSocket C Server and JavaScript Client

A basic WebSocket server implemented in C using OpenSSL for the
WebSocket handshake and a JavaScript client using Node.js for communication. It establishes a
WebSocket connection, allowing messages to be sent between the server and the client.

To run the server:

```shell
make run
```

To run the client:

```shell
cd example_client
nvm use
npm i
npm run dev
```
