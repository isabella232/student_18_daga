package daga

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
)

// create a context with c clients, len(serverKeys) servers whose private keys are in serverKeys to be used in tests
func GenerateContext(suite Suite, c int, serverKeys []kyber.Scalar) ([]Client, []Server, AuthenticationContext, error) {
	// TODO rename setup ?
	return generateContext(suite, c, 0, serverKeys)
}

// creates a context to be used in the tests
func generateTestContext(suite Suite, c, s int) ([]Client, []Server, AuthenticationContext, error) {
	return generateContext(suite, c, s, nil)
}

// TODO doc
func generateContext(suite Suite, c, s int, optServerKeys []kyber.Scalar) ([]Client, []Server, AuthenticationContext, error) {
	if c <= 0 {
		return nil, nil, nil, fmt.Errorf("invalid number of client: %d", c) // ...
	}

	if s <= 0 && len(optServerKeys) == 0 {
		return nil, nil, nil, fmt.Errorf("invalid number of servers: %d", s)
	}

	if s > 0 && len(optServerKeys) != 0 {
		return nil, nil, nil, errors.New("invalid number of servers: cannot specify both s and optServerKeys")
	}

	//Generates s servers
	var serverKeys []kyber.Point
	var servers []Server
	if len(optServerKeys) != 0 {
		s = len(optServerKeys)
		serverKeys = make([]kyber.Point, 0, s)
		servers = make([]Server, 0, s)
	} else {
		optServerKeys = make([]kyber.Scalar, s)
	}
	for i := 0; i < s; i++ {
		server, _ := NewServer(suite, i, optServerKeys[i])
		serverKeys = append(serverKeys, server.PublicKey())
		servers = append(servers, server)
	}

	//Generates the per-round secrets for the ServerSignature and keep track of the commits
	perRoundSecretCommits := make([]kyber.Point, 0, s)
	for i, serv := range servers {
		R, server := GenerateNewRoundSecret(suite, serv)
		perRoundSecretCommits = append(perRoundSecretCommits, R)
		servers[i] = server
	}

	//Generates c clients with their per-round generators
	clientKeys := make([]kyber.Point, 0, c)
	clients := make([]Client, 0, c)
	clientGenerators := make([]kyber.Point, 0, c)
	for i := 0; i < c; i++ {
		client, _ := NewClient(suite, i, nil)

		clientKeys = append(clientKeys, client.PublicKey())
		clients = append(clients, client)

		generator, err := GenerateClientGenerator(suite, i, perRoundSecretCommits)
		if err != nil {
			return nil, nil, nil, errors.New("error while generating client's generators:\n" + err.Error())
		}
		clientGenerators = append(clientGenerators, generator)
	}

	if context, err := NewAuthenticationContext(clientKeys, serverKeys, perRoundSecretCommits, clientGenerators); err != nil {
		return nil, nil, nil, errors.New("failed to create AuthenticationContext: " + err.Error())
	} else {
		return clients, servers, context, nil
	}
}
