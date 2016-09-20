var fs = require('fs');
var ProtoBuf = require('protobufjs');
var grpc = require('grpc');

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
      callback(null, {"json_data": JSON.stringify(res)});
    } catch (e) {
      callback(e, {});
    }
  }
});

server.bind(
  '127.0.0.1:50051',
  grpc.ServerCredentials.createInsecure()
);
server.start();

