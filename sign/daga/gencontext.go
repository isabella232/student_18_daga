package daga

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"io"
)

//generateClientGenerator generates a per-round generator for a given client
func generateClientGenerator(index int, commits *[]kyber.Point) (gen kyber.Point, err error) {
	if index < 0 {
		return nil, fmt.Errorf("Wrond index: %d", index)
	}
	if len(*commits) <= 0 {
		return nil, fmt.Errorf("Wrong commits:\n%v", commits)
	}
	// QUESTION FIXME why sha3(sha512()) was previously used ?
	// TODO remember that I didn't write it, see later when building service if correct etc..
	// QUESTION should we ensure that no 2 client get same generator ?
	hasher := sha512.New()
	var writer io.Writer = hasher // ...
	idb := make([]byte, 4)
	binary.BigEndian.PutUint32(idb, uint32(index)) // TODO verify
	writer.Write(idb)
	for _, R := range *commits {
		R.MarshalTo(writer)
	}
	hash := hasher.Sum(nil)
	hasher = suite.Hash()
	hasher.Write(hash)
	gen = suite.Point().Mul(suite.Scalar().SetBytes(hasher.Sum(nil)), nil)
	return
}

// creates a context to be used in the tests
func generateTestContext(c, s int) ([]Client, []Server, *authenticationContext, error) {
	if c <= 0 {
		return nil, nil, nil, fmt.Errorf("invalid number of client: %d", c) // ...
	}

	if s <= 0 {
		return nil, nil, nil, fmt.Errorf("invalid number of client: %d", s)
	}

	//Generates s servers
	serverKeys := make([]kyber.Point, 0, s)
	servers := make([]Server, 0, s)
	for i := 0; i < s; i++ {
		new, _ := NewServer(i, nil)
		serverKeys = append(serverKeys, new.PublicKey())
		servers = append(servers, new)
	}

	//Generates the per-round secrets for the ServerSignature and keep track of the commits
	perRoundSecretCommits := make([]kyber.Point, 0, s)
	for i, serv := range servers {
		R, server := generateNewRoundSecret(serv)
		perRoundSecretCommits = append(perRoundSecretCommits, R)
		servers[i] = server
	}

	//Generates c clients with their per-round generators
	clientKeys := make([]kyber.Point, 0, c)
	clients := make([]Client, 0, c)
	clientGenerators := make([]kyber.Point, 0, c)
	for i := 0; i < c; i++ {
		new, _ := NewClient(i, nil)

		clientKeys = append(clientKeys, new.key.Public)
		clients = append(clients, *new)

		generator, err := generateClientGenerator(i, &perRoundSecretCommits)
		if err != nil {
			return nil, nil, nil, errors.New("error while generating client's generators:\n" + err.Error())
		}
		clientGenerators = append(clientGenerators, generator)
	}

	if context, err := NewAuthenticationContext(clientKeys, serverKeys, perRoundSecretCommits, clientGenerators); err != nil {
		return nil, nil, nil, errors.New("failed to create authenticationcontext: " + err.Error())
	} else {
		return clients, servers, context, nil
	}
}
