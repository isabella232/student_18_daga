package main

import (
	"errors"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/dagacothority"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/gorilla/websocket"
	"net/http"
)

var suite = daga.NewSuiteEC()

func main() {
	http.HandleFunc("/dagadaemon/ws", func(w http.ResponseWriter, r *http.Request) {

		// upgrade http to websocket
		upgrader := websocket.Upgrader{
			ReadBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				log.Infof("Origin: %s", origin)
				whiteList := []string{"http://opapp.poc:5556", "http://172.17.0.1:5556", "http://172.18.0.1:5556"}
				for _, allowed := range whiteList {
					if origin == allowed {
						return true
					}
				}
				return false
			},
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Error(err)
			return
		}
		defer func() {
			if err := conn.Close(); err != nil {
				log.Error(err)
			}
		}()

		// receive client and context from webUI (via websocket)
		network.RegisterMessages(dagacothority.Context{}, dagacothority.NetClient{}, dagacothority.Auth{})
		context, err := readContext(conn)
		if err != nil {
			log.Error(err)
			return
		}

		client, err := readClient(conn)
		if err != nil {
			log.Error(err)
			return
		}

		// build daga auth. msg (call PKClient endpoint to build proof, then build correct auth. msg)

		// abstraction of remote servers/verifiers for PKclient, it is a function that wrap an API call to PKclient
		PKclientVerifier := client.NewPKclientVerifier(*context, context.Roster.RandomServerIdentity())
		M0, err := daga.NewAuthenticationMessage(suite, context, client, PKclientVerifier)
		if err != nil {
			log.Error(errors.New("failed to build new authentication message: " + err.Error()))
			return
		}

		// pipe result into websocket connection
		authMsg := dagacothority.NetEncodeAuthenticationMessage(*context, *M0) // to protobuf friendly type
		authMsgProto, err := network.Marshal(authMsg)                          // proto msg
		if err != nil {
			log.Error(err)
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, authMsgProto); err != nil {
			log.Error(err)
		}
		log.Info("authMsg sent to webUI")
	})

	err := http.ListenAndServe("127.0.0.1:9999", nil)
	if err != nil {
		log.Fatal("dagadaemon: ListenAndServe: ", err)
	}
}

func readClient(conn *websocket.Conn) (*dagacothority.Client, error) {
	if contextPtr, err := readProto(conn); err != nil {
		return nil, errors.New("readClient: " + err.Error())
	} else if netClient, ok := contextPtr.(*dagacothority.NetClient); !ok {
		return nil, errors.New("readClient: type assertion error, expected NetClient")
	} else {
		return netClient.NetDecode()
	}
}

func readContext(conn *websocket.Conn) (*dagacothority.Context, error) {
	if contextPtr, err := readProto(conn); err != nil {
		return nil, errors.New("readContext: " + err.Error())
	} else if ctx, ok := contextPtr.(*dagacothority.Context); !ok {
		return nil, errors.New("readContext: type assertion error, expected Context")
	} else {
		return ctx, nil
	}
}

func readProto(conn *websocket.Conn) (network.Message, error) {
	_, proto, err := conn.ReadMessage()
	if err != nil {
		return nil, errors.New("readProto: " + err.Error())
	}
	if _, msg, err := network.Unmarshal(proto, suite); err != nil {
		return nil, errors.New("readProto: " + err.Error())
	} else {
		return msg, nil
	}
}
