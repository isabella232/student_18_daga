// bundle all proto files in ../proto to a single skeleton.js file written under src/models/
const protobuf = require("protobufjs");
const fs = require("fs");

const root = new protobuf.Root();
root.define("cothority");

const regex = /^.*\.proto$/;
const protoPath = "../proto/";

const modelPath = "src/models/skeleton.js";

fs.readdir(protoPath, (err, items) => {
    items.forEach(file => {
        const fullPath = protoPath + file;
        console.log(fullPath);
        if (regex.test(fullPath)) {
            root.loadSync(fullPath);
        }
    });
    fs.writeFileSync(modelPath, `export default '${JSON.stringify(root.toJSON())}';`);
    console.log();
    console.log("JSON models written in " + modelPath);
});
