var fs = require('fs');
var ProtoBuf = require('protobufjs');
var grpc = require('grpc');


function log(data) {
  fs.writeFileSync('./client_log', data, {
    'encoding': 'utf8',
    'mode': 0o600,
    'flag': 'a'
  });
}

/*
process.stdin.setEncoding('utf8');
process.stdin.on('readable', () => {
  var chunk = process.stdin.read();
  if (chunk !== null) {
    fs.writeFileSync('./client_stdout', chunk, {
      'encoding': 'utf8',
      'mode': 0o600,
      'flag': 'a'
    });
  }
});
*/



var proto_data = fs.readFileSync(__dirname + "/../proto/service.proto");
var proto_desc = grpc.loadObject(ProtoBuf.loadProto(proto_data, null, "service.proto").ns);

console.log(proto_desc);
var evalpipe = proto_desc.evalpipe;

var server = new grpc.Server();
server.addProtoService(evalpipe.EvalPipe.service, {
  evaluate: function(call, callback) {
    let res;
    try {
      res = eval(call.request.script);
      log(JSON.stringify(res) + "\n");

      callback(null, {"json_data": JSON.stringify(res)});
    } catch (e) {
      callback(e, {});
    }
  }
});

const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  terminal: false
});

rl.on('line', (line) => {
  rl.close();
  let pieces = line.split(":");

  let server_cert = Buffer.from(pieces[0], 'base64');
  let server_key = Buffer.from(pieces[1], 'base64');
  let client_cacert = Buffer.from(pieces[2], 'base64');

  //console.log = log;
  console.log("running\n");  
  console.log(server_cert.toString());
  console.log(server_key.toString());
  console.log(client_cacert.toString());

  server.bind(
    '127.0.0.1:50051',
    //grpc.ServerCredentials.createInsecure()
    grpc.ServerCredentials.createSsl(
      //null,
      client_cacert,
      [{
        cert_chain: server_cert,
        private_key: server_key
      }],
      true
    )
  );
  server.start();
});


