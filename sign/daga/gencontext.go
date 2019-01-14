package daga

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/xof/blake2xb"
	"strconv"
)

// create a context with c clients, len(serverKeys) servers whose private keys are in serverKeys, to be used in tests
func GenerateContext(suite Suite, c int, serverKeys []kyber.Scalar) ([]Client, []Server, AuthenticationContext, error) {
	return generateContext(suite, c, 0, serverKeys)
}

// creates a context with c clients and s servers, to be used in the tests
func GenerateTestContext(suite Suite, c, s int) ([]Client, []Server, AuthenticationContext, error) {
	return generateContext(suite, c, s, nil)
}

func generateContext(suite Suite, c, s int, optServerKeys []kyber.Scalar) ([]Client, []Server, AuthenticationContext, error) {
	if c <= 0 {
		return nil, nil, nil, fmt.Errorf("invalid number of client: %d", c) // ...
	}

	if s <= 0 && len(optServerKeys) == 0 {
		return nil, nil, nil, fmt.Errorf("invalid number of servers: %d", s)
	}

	// TODO alternatively specify only optServerKeys
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
	for _, serv := range servers {
		R := GenerateNewRoundSecret(suite, serv)
		perRoundSecretCommits = append(perRoundSecretCommits, R)
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

	if context, err := NewMinimumAuthenticationContext(clientKeys, serverKeys, perRoundSecretCommits, clientGenerators); err != nil {
		return nil, nil, nil, errors.New("failed to create AuthenticationContext: " + err.Error())
	} else {
		return clients, servers, context, nil
	}
}

// GenerateClientGenerator generates a per-round generator for a given client
//
// commits are the commitments of the servers to their per-round secret
func GenerateClientGenerator(suite Suite, index int, commits []kyber.Point) (gen kyber.Point, err error) {
	if index < 0 {
		return nil, fmt.Errorf("GenerateClientGenerator: bad index: %d", index)
	}
	if len(commits) <= 0 {
		return nil, fmt.Errorf("GenerateClientGenerator: bad commits:\n%v", commits)
	}
	hasher := suite.Hash()
	hasher.Write([]byte(strconv.Itoa(index)))
	if pointBytes, err := PointArrayToBytes(commits); err != nil {
		return nil, err
	} else {
		hasher.Write(pointBytes)
	}
	hash := hasher.Sum(nil)

	// generator s.t. no one knows the relation between it and g, the public base/generator
	//
	// uses a xof seeded with bytes = H(index||R) as arg to Pick() instead of UnmarshalBinary(bytes)
	// because seems  that not any 32byte value can be decoded into a point..
	// (and hence seems that kyber don't use the definitions in rfc7748 and instead the curve is based on Ed25519 primitives and algos or a mix don't know)
	// using the xof as a cipher stream we can try to pick multiple times until one point is valid
	gen = suite.Point().Pick(blake2xb.New(hash))
	//gen = suite.Point()
	//if err = gen.UnmarshalBinary(hasher.Sum(nil)); err != nil {
	//	return nil, errors.New("GenerateClientGenerator: failed to pick generator, unexpected error: " + err.Error())
	//}

	// TODO additionally if we want to be completely correct we maybe need to check that :
	////////////////
	// from https://cr.yp.to/ecdh.html:
	//	There are some unusual non-Diffie-Hellman elliptic-curve protocols that need to ensure ``contributory'' behavior.
	// In those protocols, you should reject the 32-byte strings that, in little-endian form, represent
	// 0, 1, 325606250916557431795983626356110631294008115727848805560023387167927233504 (which has order 8),
	// 39382357235489614581723060781553021112529911719440698176882885853963445705823 (which also has order 8),
	// 2^255 - 19 - 1, 2^255 - 19, 2^255 - 19 + 1,
	// 2^255 - 19 + 325606250916557431795983626356110631294008115727848805560023387167927233504,
	// 2^255 - 19 + 39382357235489614581723060781553021112529911719440698176882885853963445705823,
	// 2(2^255 - 19) - 1, 2(2^255 - 19), and 2(2^255 - 19) + 1.
	// But these exclusions are unnecessary for Diffie-Hellman.
	////////////////
	// (we don't use exclusively DH and even for DH I doubt that we can spare ourselves the check since I doubt that kyber
	// implements the X25519 function in mul and the secrets obtained through key generator interface are not of the correct shape currently (bug))
	// however I don't have the time to reverse engineer/understand what kyber does and why !
	// (our curve seems to be based on Ed25519 definitions/implementations, but maybe since curve are equivalents this applies too,
	// then if it the case (I believe), a quick check using the following snippet shows that some
	// (but not all, notably the points of order 8 are correctly rejected)
	// of the bad points are accepted by current implementation !

	//for desc, bytes := range map[string][]byte{
	//	"zero": make([]byte, 32),
	//	"one"				: []byte("\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	//	"1st order8 point"	: []byte("\xe0\xebz|;A\xb8\xae\x16V\xe3\xfa\xf1\x9f\xc4j\xda\t\x8d\xeb\x9c2\xb1\xfd\x86b\x05\x16_I\xb8\x00"),
	//	"2nd order8 point"	: []byte("_\x9c\x95\xbc\xa3P\x8c$\xb1\xd0\xb1U\x9c\x83\xef[\x04D\\\xc4X\x1c\x8e\x86\xd8\"N\xdd\xd0\x9f\x11W"),
	//	"2^255 - 19 - 1"	: []byte("\xec\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f"),
	//	"2^255 - 19"		: []byte("\xed\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f"),
	//	"2^255 - 19 + 1"	: []byte("\xee\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f"),
	//	"2^255 - 19 + 325606250916557431795983626356110631294008115727848805560023387167927233504" :
	//	[]byte("\xcd\xebz|;A\xb8\xae\x16V\xe3\xfa\xf1\x9f\xc4j\xda\t\x8d\xeb\x9c2\xb1\xfd\x86b\x05\x16_I\xb8\x80"),
	//	"2^255 - 19 + 39382357235489614581723060781553021112529911719440698176882885853963445705823":
	//	[]byte("L\x9c\x95\xbc\xa3P\x8c$\xb1\xd0\xb1U\x9c\x83\xef[\x04D\\\xc4X\x1c\x8e\x86\xd8\"N\xdd\xd0\x9f\x11\xd7"),
	//	"2(2^255 - 19) - 1"	: []byte("\xd9\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"),
	//	"2(2^255 - 19)"		: []byte("\xda\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"),
	//	"2(2^255 - 19) + 1"	: []byte("\xdb\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"),
	//}{
	//	point := suite.Point()
	//	if err := point.UnmarshalBinary(bytes); err != nil {
	//		fmt.Println("ok\t" + desc + " correctly rejected(" + err.Error() + ")")
	//	}else {
	//		fmt.Println("ko\t" + desc + " accepted: " + point.String())
	//	}
	//}
	//output:
	//ko	one accepted: 0100000000000000000000000000000000000000000000000000000000000000
	//ok	1st order8 point correctly rejected(invalid Ed25519 curve point)
	//ok	2^255 - 19 + 325606250916557431795983626356110631294008115727848805560023387167927233504 correctly rejected(invalid Ed25519 curve point)
	//ok	2(2^255 - 19) - 1 correctly rejected(invalid Ed25519 curve point)
	//ko	2(2^255 - 19) + 1 accepted: dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
	//ko	2(2^255 - 19) accepted: daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
	//ko	zero accepted: 0000000000000000000000000000000000000000000000000000000000000000
	//ok	2nd order8 point correctly rejected(invalid Ed25519 curve point)
	//ko	2^255 - 19 - 1 accepted: ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
	//ko	2^255 - 19 accepted: 0000000000000000000000000000000000000000000000000000000000000000
	//ko	2^255 - 19 + 1 accepted: 0100000000000000000000000000000000000000000000000000000000000000
	//ko	2^255 - 19 + 39382357235489614581723060781553021112529911719440698176882885853963445705823 accepted: 4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7

	// TODO remember to implement potentially other, concrete suite related, checks when/if others suites added
	//	=> maybe define a checkPointCorrect/pickCorrectPoint function in daga Suite, where concrete suite do what needs to be done
	//  the above implementation should work well enough for suiteEC
	return
}
