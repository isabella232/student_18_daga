# Web-interface to the daga cothority service

The cothority-services can interact using protobuf over websockets with other
languages. This directory provides the tools used to interact with the daga service's endpoints from JS.

`bundle.js` is a compilation of the `src/`-directory.

the proto files are searched in ../proto

## Updating `bundle.js`

If you change the protobuf (.proto) files or add new ones, you need to compile them
so they're available under javascript.
The protobuf-files are stored under `../proto/`. if you add a new file,
it will be automatically picked up by the compilation-scipt.
To compile all protobuf-files to `bundle.js`, launch the following:

```bash
make
```

This supposes you have `node` and `npm` installed, and will create a new
`bundle.js`.

## `DagaMessages`

The main class in javascript that contains helper-functions for every
method of the service-api. It is not created automatically. So if you
add new proto-files or new messages to it, you need to extend it manually.
The class is defined in `src/daga.js` and has some helper methods:

### createSocket

`createSocket` is a simple method to encode javascript-objects using
protobuf and send it through websockets to the service.

### toml_to_roster

Converts a toml-string of public.toml to a roster that can be sent
to a service. Also calculates the Id of the ServerIdentities.

### si_to_ws

Returns a websocket-url from a ServerIdentity.

