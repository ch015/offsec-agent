const { Server } = require('socket.io');

const io = new Server(3000);

io.on('connection', (socket) => {
  socket.on('message', (data) => {
    handleMessage(data);
  });
});
