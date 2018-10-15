package daga_login

import (
	"github.com/dedis/kyber"
	"github.com/dedis/student_18_daga/sign/daga"
)

//Server is used to store a daga.Server and TODO whatever I'll need that is not needed by kyber.daga
type Server struct {
	daga.Server
}

//CreateServer is used to initialize a new server with a given index
//If no private key is given, a random one is chosen
func NewServer(i int, s kyber.Scalar) (server *Server, err error) {
	if dagaServer, err := daga.NewServer(suite, i, s); err != nil {
		return nil, err
	} else {
		return &Server{
			dagaServer,
		}, nil
	}
}