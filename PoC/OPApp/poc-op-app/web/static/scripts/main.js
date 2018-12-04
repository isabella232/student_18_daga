// FIXME instead of serving such JS, package it in new file and inject it using greasemonkey script or put it in a webextension, to prevent server doing anything wrong (user supplied code)
// FIXME/TODO create modules and use correctly requiresJS, QUESTION how to require protobufjs here..instead of script tag in html

let Main = {
    data: {
        contextFileArrayBuffer: undefined,
        clientFileArrayBuffer: undefined,
        authArrayBuffer: undefined,
        //serversToml: undefined
    },
    utils: {
        // ArrayBuffer to string, used to read text files (containing only the first 256 code point of unicode should be fine)
        // (TODO find real/robust conversion...look at fromCharCode doc...) https://stackoverflow.com/questions/13356493/decode-utf-8-with-javascript
        ab2str: (buf) => String.fromCharCode.apply(null, new Uint8Array(buf)),

        readFile: (fromElem) => (next) => () => {
            const files = fromElem.files;
            const file = files[0];
            const reader = new FileReader();
            reader.onload = function () {
                let msg = "done loading file: ";
                const fileArrayBuffer = reader.result;
                console.log(fileArrayBuffer);
                if (next !== undefined) {
                    next(fileArrayBuffer);
                }
            };
            reader.readAsArrayBuffer(file)
        },

        thenSaveUnder: (fieldName) => (data) => {
            switch (fieldName) {  // until I find a way to pass by ref...
                case "context":
                    Main.data.contextFileArrayBuffer = data;
                    break;
                case "client":
                    Main.data.clientFileArrayBuffer = data;
                    break;
                // case "roster":
                //     const tomlString = Main.utils.ab2str(data);
                //     Main.data.serversToml = tomlString;
                //     console.log(tomlString);
                //     break;
            }
        }
    }
};

// cothority related stuff, load bundle
require.config({
    paths: {
        "protobufjs":   "protobuf.min",
        "jquery":       "jquery-3.3.1.min",
        //"topl":         "topl.min",  //TODO FIXME for later, understand how to load it using requirejs amd way of doing things, seems that this module is not compatible..
        // TODO and I guess same problem for UUID
    },
});
requirejs(["jquery", "bundle"],
function($, DagaProtobuf) {
    //This function is called when scripts/bundle.js is loaded.
    //If bundle.js calls define(), then this function is not fired until
    //bundle's dependencies have loaded, and the DagaProtobuf argument will hold
    //the module value for "bundle".

    // DOM elems
    const contextElem = document.getElementById('contextSelector');
    const clientElem = document.getElementById('clientSelector');
    // const rosterElem = document.getElementById('rosterSelector');
    const authFormElem = document.getElementById("authForm");
    const authFormBtnElem = authFormElem.querySelector('button');

    // user input
    const readFile = Main.utils.readFile;
    const thenSaveUnder = Main.utils.thenSaveUnder;
    contextElem.onchange = readFile(contextElem)(thenSaveUnder("context"));
    clientElem.onchange = readFile(clientElem)(thenSaveUnder("client"));
    // rosterElem.onchange = readFile(rosterElem)(thenSaveUnder("roster"));

    // let getting_status = false;
    // let sockStatus;
    // function getStatus() {
    //     if (getting_status) {
    //         console.log("waiting for status");
    //         return;
    //     }
    //     const serversToml = Main.data.serversToml;
    //     if (serversToml === undefined) {
    //         alert("Please load a public.toml-file");
    //         return;
    //     }
    //     getting_status = true;
    //
    //     const roster = DagaProtobuf.toml_to_roster(serversToml);
    //     // send request (yes the createSocket ..send..) + why this is not in dagaprotobuf ? ? poor API poor user...poor me..
    //     DagaProtobuf.createSocket(sockStatus,
    //         DagaProtobuf.si_to_ws(roster.servers[0], "/Status/Request"),
    //         DagaProtobuf.createStatusRequest(),
    //         (reply) => {  // on success this is called with reply
    //             let decoded = DagaProtobuf.decodeStatusResponse(reply);
    //             alert(JSON.stringify(decoded));
    //             getting_status = false;
    //         }, (error) => {  // on error this is called
    //             alert(error);
    //             getting_status = false;
    //         }
    //     );
    // }

    const thenPostIt = (authMsg) => {
        if (authMsg === undefined) {
            console.log(error);
            return;
        }
        // postback
        $.post({
            url: window.location,
            processData: false,
            contentType: 'application/octet-stream',
            data: authMsg,
            success: (data) => {
                console.log("success");
                console.log(data);
                window.location.replace(data.redirect);
            },
            error: (ts) => {console.error(ts)},
        });
        console.log("POSTed");
    };
    const buildAuthMsg = () => (next) => () => {
        // if (authenticating) {
        //     console.log("waiting for authentication result");
        //     return;
        // }

        if (next === undefined) {
            console.error("buildAuthMsg: next undefined");
            return
        }

        // load args from webUI
        const context = Main.data.contextFileArrayBuffer;
        if (context === undefined) {
            const error ="Please load a daga context, under which you want to authenticate";
            alert(error);
            return
        }
        const client = Main.data.clientFileArrayBuffer;
        if (client === undefined) {
            const error = "Please load the daga client you want to authenticate, TODO/later or just (index, privatekey)";
            alert(error);
            return
        }
        // authenticating = true;  // TODO instead of this ugly scheme disable button

        // open connection to local daga daemon
        let msgConn = new WebSocket("ws://127.0.0.1:9999/dagadaemon/ws");
        msgConn.onclose = function (evt) {
            console.log(evt);
            console.log("Connection closed");
            // authenticating = false;
        };

        // forward command to local daemon that will give us back the authmsg
        msgConn.onopen = function(evt) {
            console.log(evt);
            msgConn.send(context);
            console.log("context sent");
            msgConn.send(client);
            console.log("client sent");
        };

        // receive result
        msgConn.onmessage = function (evt) {
            // Main.data.authArrayBuffer = evt.data;
            let authMsg = evt.data;
            console.log("received: ");
            console.log(authMsg);
            next(authMsg);
        };
    };

    // Auth:
    // - generate a new authentication message (ask local daga daemon to to it for us),
    // - then post it back to OP/IdP that will take care to continue the auth. process
    authFormBtnElem.onclick = buildAuthMsg()(thenPostIt);
});

