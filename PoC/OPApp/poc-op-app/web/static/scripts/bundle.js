define(['protobufjs'], function (protobuf) { 'use strict';

protobuf = 'default' in protobuf ? protobuf['default'] : protobuf;

var skeleton = '{"nested":{"cothority":{},"dagacothority":{"nested":{"CreateContext":{"fields":{"serviceid":{"rule":"required","type":"bytes","id":1},"signature":{"rule":"required","type":"bytes","id":2},"subscriberskeys":{"rule":"repeated","type":"bytes","id":3},"daganodes":{"type":"onet.Roster","id":4}}},"CreateContextReply":{"fields":{"context":{"rule":"required","type":"Context","id":1}}},"PKclientCommitments":{"fields":{"context":{"rule":"required","type":"Context","id":1},"commitments":{"rule":"repeated","type":"bytes","id":2}}},"PKclientChallenge":{"fields":{"cs":{"rule":"required","type":"bytes","id":1},"sigs":{"rule":"repeated","type":"ServerSignature","id":2,"options":{"packed":false}}}},"ServerSignature":{"fields":{"index":{"rule":"required","type":"sint32","id":1},"sig":{"rule":"required","type":"bytes","id":2}}},"Auth":{"fields":{"context":{"rule":"required","type":"Context","id":1},"scommits":{"rule":"repeated","type":"bytes","id":2},"t0":{"rule":"required","type":"bytes","id":3},"proof":{"rule":"required","type":"ClientProof","id":4}}},"AuthReply":{"fields":{"request":{"rule":"required","type":"Auth","id":1},"tags":{"rule":"repeated","type":"bytes","id":2},"proofs":{"rule":"repeated","type":"ServerProof","id":3,"options":{"packed":false}},"indexes":{"rule":"repeated","type":"sint32","id":4,"options":{"packed":false}},"sigs":{"rule":"repeated","type":"ServerSignature","id":5,"options":{"packed":false}}}},"ServerProof":{"fields":{"t1":{"rule":"required","type":"bytes","id":1},"t2":{"rule":"required","type":"bytes","id":2},"t3":{"rule":"required","type":"bytes","id":3},"c":{"rule":"required","type":"bytes","id":4},"r1":{"rule":"required","type":"bytes","id":5},"r2":{"rule":"required","type":"bytes","id":6}}},"Context":{"fields":{"contextid":{"rule":"required","type":"bytes","id":1},"serviceid":{"rule":"required","type":"bytes","id":2},"signatures":{"rule":"repeated","type":"bytes","id":3},"x":{"rule":"repeated","type":"bytes","id":4},"y":{"rule":"repeated","type":"bytes","id":5},"r":{"rule":"repeated","type":"bytes","id":6},"h":{"rule":"repeated","type":"bytes","id":7},"roster":{"type":"onet.Roster","id":8}}},"ClientProof":{"fields":{"cs":{"rule":"required","type":"PKclientChallenge","id":1},"t":{"rule":"repeated","type":"bytes","id":2},"c":{"rule":"repeated","type":"bytes","id":3},"r":{"rule":"repeated","type":"bytes","id":4}}}}},"onet":{"nested":{"Roster":{"fields":{"id":{"rule":"required","type":"bytes","id":1},"list":{"rule":"repeated","type":"network.ServerIdentity","id":2,"options":{"packed":false}},"aggregate":{"rule":"required","type":"bytes","id":3}}}}},"network":{"nested":{"ServerIdentity":{"fields":{"public":{"rule":"required","type":"bytes","id":1},"id":{"rule":"required","type":"bytes","id":2},"address":{"rule":"required","type":"string","id":3},"description":{"rule":"required","type":"string","id":4},"url":{"type":"string","id":5}}}}},"StatusRequest":{"fields":{}},"StatusResponse":{"fields":{"system":{"keyType":"string","type":"Status","id":1},"server":{"type":"network.ServerIdentity","id":2}},"nested":{"Status":{"fields":{"field":{"keyType":"string","type":"string","id":1}}}}}}}';

var Root = protobuf.Root;

/**
 * As we need to create a bundle, we cannot use the *.proto files and the a script will wrap
 * them in a skeleton file that contains the JSON representation that can be used in the js code
 */

var Root$1 = Root.fromJSON(JSON.parse(skeleton));

var classCallCheck = function (instance, Constructor) {
  if (!(instance instanceof Constructor)) {
    throw new TypeError("Cannot call a class as a function");
  }
};

var createClass = function () {
  function defineProperties(target, props) {
    for (var i = 0; i < props.length; i++) {
      var descriptor = props[i];
      descriptor.enumerable = descriptor.enumerable || false;
      descriptor.configurable = true;
      if ("value" in descriptor) descriptor.writable = true;
      Object.defineProperty(target, descriptor.key, descriptor);
    }
  }

  return function (Constructor, protoProps, staticProps) {
    if (protoProps) defineProperties(Constructor.prototype, protoProps);
    if (staticProps) defineProperties(Constructor, staticProps);
    return Constructor;
  };
}();









var inherits = function (subClass, superClass) {
  if (typeof superClass !== "function" && superClass !== null) {
    throw new TypeError("Super expression must either be null or a function, not " + typeof superClass);
  }

  subClass.prototype = Object.create(superClass && superClass.prototype, {
    constructor: {
      value: subClass,
      enumerable: false,
      writable: true,
      configurable: true
    }
  });
  if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass;
};











var possibleConstructorReturn = function (self, call) {
  if (!self) {
    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
  }

  return call && (typeof call === "object" || typeof call === "function") ? call : self;
};

/**
 * Base class for the protobuf library that provides helpers to encode and decode
 * messages according to a given model
 *
 * @author Gaylor Bosson (gaylor.bosson@epfl.ch)
 */

var CothorityProtobuf = function () {

  /**
   * @constructor
   */
  function CothorityProtobuf() {
    classCallCheck(this, CothorityProtobuf);

    this.root = Root$1;
  }

  /**
   * Encode a model to be transmitted over websocket
   * @param {String} name
   * @param {Object} fields
   * @returns {*|Buffer|Uint8Array}
   */


  createClass(CothorityProtobuf, [{
    key: 'encodeMessage',
    value: function encodeMessage(name, fields) {
      var model = this.getModel(name);

      // Create the message with the model
      var msg = model.create(fields);

      // Encode the message in a BufferArray
      return model.encode(msg).finish();
    }

    /**
     * Decode a message coming from a websocket
     * @param {String} name
     * @param {*|Buffer|Uint8Array} buffer
     */

  }, {
    key: 'decodeMessage',
    value: function decodeMessage(name, buffer) {
      var model = this.getModel(name);
      return model.decode(buffer);
    }

    /**
     * Return the protobuf loaded model
     * @param {String} name
     * @returns {ReflectionObject|?ReflectionObject|string}
     */

  }, {
    key: 'getModel',
    value: function getModel(name) {
      return this.root.lookup('' + name);
    }
  }]);
  return CothorityProtobuf;
}();

//import * as topl from './topl.min.js'

/**
 * Helpers to encode and decode messages of the daga Cothority service
 *
 * @author Gaylor Bosson (gaylor.bosson@epfl.ch)
 * @author Lucas Pires (lucas.pires@epfl.ch)
 */

var DagaMessages = function (_CothorityProtobuf) {
    inherits(DagaMessages, _CothorityProtobuf);

    function DagaMessages() {
        classCallCheck(this, DagaMessages);
        return possibleConstructorReturn(this, (DagaMessages.__proto__ || Object.getPrototypeOf(DagaMessages)).apply(this, arguments));
    }

    createClass(DagaMessages, [{
        key: 'createStatusRequest',


        // /**
        //  * Create an encoded message to make a ClockRequest to a cothority node
        //  * @param {Array} servers - list of ServerIdentity
        //  * @returns {*|Buffer|Uint8Array}
        //  */
        // createClockRequest(servers) {
        //     const fields = {
        //         Roster: {
        //             List: servers
        //         }
        //     };
        //     return this.encodeMessage('ClockRequest', fields);
        // }
        //
        // /**
        //  * Return the decoded response of a ClockRequest
        //  * @param {*|Buffer|Uint8Array} response - Response of the Cothority
        //  * @returns {Object}
        //  */
        // decodeClockResponse(response) {
        //     response = new Uint8Array(response);
        //
        //     return this.decodeMessage('ClockResponse', response);
        // }
        //
        // /**
        //  * Create an encoded message to make a CountRequest to a cothority node
        //  * @returns {*|Buffer|Uint8Array}
        //  */
        // createCountRequest() {
        //     return this.encodeMessage('CountRequest', {});
        // }
        //
        // /**
        //  * Return the decoded response of a CountRequest
        //  * @param {*|Buffer|Uint8Array} response - Response of the Cothority
        //  * @returns {*}
        //  */
        // decodeCountResponse(response) {
        //     response = new Uint8Array(response);
        //
        //     return this.decodeMessage('CountResponse', response);
        // }
        //

        /**
         * Create an encoded message to make a StatusRequest to a cothority node
         * @returns {*|Buffer|Uint8Array}
         */
        value: function createStatusRequest() {
            return this.encodeMessage('StatusRequest', {});
        }

        /**
         * Return the decoded response of a StatusRequest
         * @param {*|Buffer|Uint8Array} response - Response of the Cothority
         * @returns {*}
         */

    }, {
        key: 'decodeStatusResponse',
        value: function decodeStatusResponse(response) {
            response = new Uint8Array(response);
            return this.decodeMessage('StatusResponse', response);
        }

        /**
         * Use the existing socket or create a new one if required
         * @param socket - WebSocket-array
         * @param address - String ws address
         * @param message - ArrayBuffer the message to send
         * @param callback - Function callback when a message is received
         * @param error - Function callback if an error occurred
         * @returns {*}
         */

    }, {
        key: 'createSocket',
        value: function createSocket(socket, address, message, callback, error) {
            if (!socket) {
                socket = {};
            }
            var sock = socket[address];
            if (!sock || sock.readyState > 2) {
                sock = new WebSocket(address);
                sock.binaryType = 'arraybuffer';
                socket[address] = sock;
            }

            function onError(e) {
                sock.removeEventListener('error', onError);
                error(e);
            }
            sock.addEventListener('error', onError);

            function onMessage(e) {
                sock.removeEventListener('message', onMessage);
                callback(e.data);
            }
            sock.addEventListener('message', onMessage);

            if (sock.readyState === 0) {
                sock.addEventListener('open', function () {
                    sock.send(message);
                });
            } else {
                sock.send(message);
            }

            return socket;
        }

        /**
         * Converts an arraybuffer to a hex-string
         * @param {ArrayBuffer} buffer
         * @returns {string} hexified ArrayBuffer
         */

    }, {
        key: 'buf2hex',
        value: function buf2hex(buffer) {
            // buffer is an ArrayBuffer
            return Array.prototype.map.call(new Uint8Array(buffer), function (x) {
                return ('00' + x.toString(16)).slice(-2);
            }).join('');
        }

        /**
         * Converts a toml-string of public.toml to a roster that can be sent
         * to a service. Also calculates the Id of the ServerIdentities.
         * @param {string} toml of public.toml
         * @returns {object} Roster-object
         */

    }, {
        key: 'toml_to_roster',
        value: function toml_to_roster(toml) {
            var parsed = {};
            var b2h = this.buf2hex;
            try {
                parsed = topl.parse(toml);
                console.log(parsed);
                parsed.servers.forEach(function (el) {
                    var pubstr = Uint8Array.from(atob(el.Public), function (c) {
                        return c.charCodeAt(0);
                    });
                    var url = "https://dedis.epfl.ch/id/" + b2h(pubstr);
                    el.Id = new UUID(5, "ns:URL", url).export();
                });
            } catch (err) {
                console.log(err);
            }
            return parsed;
        }

        /**
         * Returns a websocket-url from a ServerIdentity
         * @param {ServerIdentity} the serveridentity to convert to a websocket-url
         * @returns {string} the url
         */

    }, {
        key: 'si_to_ws',
        value: function si_to_ws(si, path) {
            // TODO signal this to the lab or make pull request to cothority template
            var ip_port = si.Address.replace("tls://", "").split(":");
            ip_port[1] = parseInt(ip_port[1]) + 1;
            return "ws://" + ip_port.join(":") + path;
        }
    }]);
    return DagaMessages;
}(CothorityProtobuf);

/**
 * Singleton
 */


var daga = new DagaMessages();

return daga;

});
