package dagacothority

import (
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/student_18_daga/sign/daga"
)

// contain net wrappers around the kyber.daga datastructures and TODO rethink whole file organization

// TODO QUESTION ask, dumb IMO but feel kind of bad exporting things that are intended to be immutable and private so the in between solution is to have a separate struct
// TODO ~messy IMO, how to do it in a idiomatic and educated way ?

// NetClient is used to represent a daga.Client (which is an interface) in a net friendly way
// used only to dump client to disk while developing for now
// ! dont send those around, contains sensitive informations !
type NetClient struct {
	PrivateKey kyber.Scalar
	Index      int
}

// NetServer is used to represent a daga.Server (which is an interface) in a net friendly way
// used only to dump server to disk while developing for now
type NetServer struct {
	PrivateKey     kyber.Scalar
	Index          int
	PerRoundSecret kyber.Scalar
}

func netEncodeClient(c daga.Client) *NetClient {
	return &NetClient{
		Index:      c.Index(),
		PrivateKey: c.PrivateKey(),
	}
}

// NetDecode is used to translate back the net friendly version of Client
func (nc NetClient) NetDecode() (*Client, error) {
	return NewClient(nc.Index, nc.PrivateKey)
}

// NetEncodeClients transform a slice of Client into a slice of NetClient (the "net friendly" version of it"
func NetEncodeClients(clients []daga.Client) ([]NetClient, error) {
	if len(clients) == 0 {
		return nil, errors.New("empty array")
	}
	var netClients []NetClient
	for _, client := range clients {
		netClient := netEncodeClient(client)
		netClients = append(netClients, *netClient)
	}
	return netClients, nil
}

//func NetDecodeClients(netClients []NetClient) ([]*Client, error) {
//	if len(netClients) == 0 {
//		return nil, errors.New("empty slice")
//	}
//	var clients []*Client
//	for i, nc := range netClients {
//		if c, err := nc.NetDecode(); err != nil {
//			return nil, fmt.Errorf("Decode error at index %d\n%s", i, err)
//		} else {
//			clients = append(clients, c)
//		}
//	}
//	return clients, nil
//}

// NetEncodeServer is used to translate a daga.Server to the net friendly version of it
func NetEncodeServer(s daga.Server) *NetServer {
	return &NetServer{
		PrivateKey:     s.PrivateKey(),
		Index:          s.Index(),
		PerRoundSecret: s.RoundSecret(),
	}
}

//func NetEncodeServers(servers []daga.Server) ([]NetServer, error) {
//	if len(servers) == 0 {
//		return nil, errors.New("empty array")
//	}
//	var netServers []NetServer
//	for _, server := range servers {
//		netServer := NetEncodeServer(server)
//		netServers = append(netServers, *netServer)
//	}
//	return netServers, nil
//}

// NetDecode is used to translate back the net friendly version of a daga.Server
func (s NetServer) NetDecode() (daga.Server, error) {
	server, err := daga.NewServer(suite, s.Index, s.PrivateKey)
	if err != nil {
		return nil, err
	}
	server.SetRoundSecret(s.PerRoundSecret)
	return server, nil
}
