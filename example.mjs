import makeMITM from  './mitm.js';
import net from 'node:net';
import fs from 'node:fs';


let {MITM} = await makeMITM();
let m = new MITM();
m.log_level = 4;

//m.generateRSAPrivateKey();
m.generateECCPrivateKey();

console.log(m.getPublicKey());
console.log(m.getPrivateKey());

//console.log(m.getPrivateKey());
let cacert = m.getCACertificate();
fs.writeFileSync("trust-me.pem", cacert, "utf-8");
console.log(cacert);

var server = net.createServer(function(socket) {
    let ssl = m.ssl();
    ssl.setPacketOutCallback(d => socket.write(d));
    ssl.setDataOutCallback(d => {
        console.log("D->", d);
        ssl.dataIn([
            'HTTP/1.1 200 OK',
            'Connection: close',
            '',
            '',
            'OK',
            ''
        ].join("\r\n"));
        ssl.dataIn(JSON.stringify(ssl.getInfo(), null, "    "));
        ssl.close();
    });
    socket.on('data', function(data) {
        console.log(data);
        ssl.packetIn(data);
    });
    socket.on('close', function() {
        console.log('Connection closed');
        ssl.delete();
    })
    socket.on('error', function() {
        console.log('Connection error');
    })
});

server.listen(4433, '127.0.0.1');

console.log("Server ready, try with curl -v --cacert trust-me.pem https://localhost:4433");
