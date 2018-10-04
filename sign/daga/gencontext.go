package daga

import (
	"crypto/sha512"
	"encoding/binary"
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

func generateTestContext(c, s int) (clients []Client, servers []Server, context *authenticationContext, err error) {
	context = &authenticationContext{}
	if c <= 0 {
		return nil, nil, nil, fmt.Errorf("Invalid number of client asked: %d", c) // ...
	}

	if s <= 0 {
		return nil, nil, nil, fmt.Errorf("Invalid number of client asked: %d", s)
	}

	//Generates s servers
	for i := 0; i < s; i++ {
		new := Server{index: i, private: suite.Scalar().Pick(suite.RandomStream())}
		context.g.y = append(context.g.y, suite.Point().Mul(new.private, nil))
		servers = append(servers, new)
	}

	//Generates the per-round secrets for the ServerSignature
	for i, serv := range servers {
		context.r = append(context.r, serv.GenerateNewRoundSecret())
		servers[i] = serv
	}

	//Generates c clients with their per-round generators
	for i := 0; i < c; i++ {
		new, _ := NewClient(i, nil)

		context.g.x = append(context.g.x, new.key.Public)
		clients = append(clients, *new)

		temp, err := GenerateClientGenerator(i, &context.r)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("Error in client's generators:\n%s", err)
		}

		context.h = append(context.h, temp)
	}

	return clients, servers, context, nil
}
