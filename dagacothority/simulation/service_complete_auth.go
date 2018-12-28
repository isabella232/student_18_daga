package main

import (
	"github.com/BurntSushi/toml"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/dedis/onet/simul/monitor"
	"github.com/dedis/student_18_daga/dagacothority"
	"github.com/dedis/student_18_daga/sign/daga"
	"math/rand"
)

/*
* Defines the simulation of auth. requests for the daga service
* (complete auth. request, including the PKClient building)
 */

func init() {
	onet.SimulationRegister("DagaAuthSimulation", NewAuthSimulation)
}

// SimServiceCompleteAuth implements the onet.Simulation interface
type SimServiceCompleteAuth struct {
	onet.SimulationBFTree
	NumClientsInContext int
}

// NewAuthSimulation returns the new simulation, where all fields are
// initialised using the toml config-file
func NewAuthSimulation(config string) (onet.Simulation, error) {
	simService := &SimServiceCompleteAuth{}
	_, err := toml.Decode(config, simService)
	if err != nil {
		return nil, err
	}
	return simService, nil
}

// Setup creates a roster from `hosts` and the tree used for that simulation.
// implements the Simulation interface.
func (s *SimServiceCompleteAuth) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 12000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

// Node can be used to initialize each node before it will be run
// by the server.
func (s *SimServiceCompleteAuth) Node(config *onet.SimulationConfig) error {
	index, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}
	log.Lvl3("Initializing node with index (in roster): ", index)
	return s.SimulationBFTree.Node(config)
}

// Run is used on the destination machine and runs a number of
// rounds
func (s *SimServiceCompleteAuth) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", s.Rounds)
	suite := daga.NewSuiteEC()

	// configure cothority, make it start serving some new context
	serviceProviderAdmin := dagacothority.NewAdminClient()
	// generate clients and retrieve their fresh keys
	subscriberKeys, clients := func(numClients int) ([]kyber.Point, []daga.Client) {
		subscriberKeys := make([]kyber.Point, 0, numClients)
		clients := make([]daga.Client, 0, numClients)
		for i := 0; i < numClients; i++ {
			client, err := daga.NewClient(suite, i, nil)
			log.ErrFatal(err)
			clients = append(clients, client)
			subscriberKeys = append(subscriberKeys, client.PublicKey())
		}
		return subscriberKeys, clients
	}(s.NumClientsInContext)
	log.Lvl1("done generating fresh clients")

	// setup, issue a CreateContext call to the dagacothority
	createContext := monitor.NewTimeMeasure("CreateContext")
	context, err := serviceProviderAdmin.CreateContext(subscriberKeys, config.Roster)
	createContext.Record()
	log.ErrFatal(err)
	log.Lvl1("CreateContext done")

	for round := 0; round < s.Rounds; round++ {
		log.Lvl1("Starting round", round)

		// the following essentially breaks/split api.Auth() (copy paste) to record different measures

		// create client
		cIdx := rand.Intn(len(context.Members().X))
		c, err := dagacothority.NewClient(clients[cIdx].Index(), clients[cIdx].PrivateKey())

		// 	TODO new service API that returns current Tx Rx then here 2 calls, one before one after + RecordSingleMeasure
		//   or have the services talk to monitor directly (possible ??) (only temp modification to gather stats) => recordcountermeasure in API method
		// TODO run those traffic tests localhost instead of deterlab if possible
		baseTx := make(map[string]uint64, len(config.Roster.List))
		for _, node := range config.Roster.List {
			reply := requestTraffic(c, node)
			baseTx[node.String()] = reply.Tx
		}

		fullAuth := monitor.NewTimeMeasure("complete auth round (including interactive proof)")

		// build daga auth. message (build interactive PK transcript by interacting with daga cothority)
		PKclientVerifier := c.NewPKclientVerifier(*context, context.Roster.RandomServerIdentity())
		proof := monitor.NewTimeMeasure("PKClient/authMsg building")
		authMsg, err := daga.NewAuthenticationMessage(suite, context, c, PKclientVerifier)
		proof.Record()
		if err != nil {
			log.Lvl1("pkclient error: " + err.Error())
		}

		// send it to random server (API call to Auth)
		request := *dagacothority.NetEncodeAuthenticationMessage(*context, *authMsg)
		reply := dagacothority.AuthReply{}
		dst := context.Roster.RandomServerIdentity()
		auth := monitor.NewTimeMeasure("Auth")
		err = c.Onet.SendProtobuf(dst, &request, &reply)
		auth.Record()
		if err != nil {
			log.Lvl1("auth error: " + err.Error())
		}
		// decode reply + extract final linkage tag
		serverMsg, _ := reply.NetDecode()
		Tf, _ := daga.GetFinalLinkageTag(suite, context, *serverMsg)

		fullAuth.Record()

		totalTraffic := uint64(0)
		for _, node := range config.Roster.List {
			baseTx := baseTx[node.String()]
			totalTraffic += requestTraffic(c, node).Tx - baseTx
		}

		monitor.RecordSingleMeasure("total server-server traffic", float64(totalTraffic))
		log.Lvlf1("final linkage tag of client %d: %v", cIdx, Tf)
	}
	return nil
}

// here because don't want to pollute exported API but..
func requestTraffic(c *dagacothority.Client, node *network.ServerIdentity) *dagacothority.TrafficReply {
	request := dagacothority.Traffic{}
	reply := dagacothority.TrafficReply{}
	log.ErrFatal(c.Onet.SendProtobuf(node, &request, &reply))
	return &reply
}
