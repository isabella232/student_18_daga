package daga

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"io"
)

/*GenerateClientGenerator generates a per-round generator for a given client*/
func GenerateClientGenerator(index int, commits *[]kyber.Point) (gen kyber.Point, err error) {
	if index < 0 {
		return nil, fmt.Errorf("Wrond index: %d", index)
	}
	if len(*commits) <= 0 {
		return nil, fmt.Errorf("Wrong commits:\n%v", commits)
	}

	// QUESTION again WTF these 2 hashes ??
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
	//rand := suite.Cipher(hash)
	gen = suite.Point().Mul(suite.Scalar().SetBytes(hasher.Sum(nil)), nil)
	return
}

// QUESTION RHAAAAAAA why this not used in scenario test + why here + fuuuuck ..
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

		// TODO verify that the previous student's code (this one) is correct
		generator, err := GenerateClientGenerator(i, &perRoundSecretCommits)
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