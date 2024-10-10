/*
Copyright (c) 2016 NCC Group Security Services, Inc. All rights reserved.
Licensed under Dual BSD/GPLv2 per the repo LICENSE file.
*/

var fs = require('fs');
var ProtoBuf = require('protobufjs');
var grpc = require('grpc');

var proto_data = fs.readFileSync(__dirname + "/../proto/service.proto");
var proto_desc = grpc.loadObject(ProtoBuf.loadProto(proto_data, null, "service.proto").ns);

var evalpipe = proto_desc.evalpipe;
var stub = new evalpipe.EvalPipe('localhost:50051', grpc.credentials.createInsecure());

stub.evaluate(process.argv.slice(2)[0], function(err, res) {
  console.log(err);
  console.log(res);
});
