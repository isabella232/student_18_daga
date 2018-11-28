// bundle all proto files in ../proto to a single skeleton.json file written under src/models/
// @author: Linus Gasser,
// adapted from https://github.com/dedis/popcoins/blob/master/app/lib/cothority/protobuf/build/build_proto.js
const protobuf = require("protobufjs");
const fs = require("fs");
const files = require("file");

const root = new protobuf.Root();
root.define("cothority");

const regex = /^.*\.proto$/;
const protoPath = "../proto/";
//files.walk("../../protobuf", (err, path, dirs, items) => {
files.walkSync(protoPath, (path, dirs, items) => {
    items.forEach(file => {
        const fullPath = path + "/" + file;
        console.log(fullPath);
        if (regex.test(fullPath)) {
            root.loadSync(fullPath);
        }
    });
});
const modelPath = "src/models/skeleton.json";
fs.writeFileSync(modelPath, JSON.stringify(root.toJSON()));
console.log();
console.log("JSON models written in " + modelPath);
