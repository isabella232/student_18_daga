package daga_login

import (
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/sign/daga"
	"io/ioutil"
)

// check if two slices of points are containing the same elements
func ContainsSameElems(a, b []kyber.Point) bool {
	// use maps to mimic set, first traverse first slice and populate map
	// then traverse second slice checking if value present in map and indeed equal (stringEq ==> eq)
	if len(a) != len(b) {
		// TODO consider removing this, and instead first range on longer slice
		// TODO (then can be used to check that slices contains same elems without discriminating the cases where one slice add other points => like when members are enrolled in a context to allow greater anonymity)
		return false
	}
	set := make(map[string]struct{}, len(a))
	exist := struct{}{}
	for _, p := range a {
		set[p.String()] = exist
	}
	for _, p := range b {
		if _, present := set[p.String()]; !present {
			return false
		}
	}
	return true
}

////helper I use in stead of having a proper bootstrap method for now
//func ReadContext(path string) (Context, error) {
//	if msg, err := read(path); err != nil {
//		return Context{}, errors.New("readContext:" + err.Error())
//	} else {
//		if netContext, ok := msg.(*NetContext); !ok {
//			return Context{}, errors.New("readContext: type assertion error, expected NetContext")
//		} else {
//			return netContext.NetDecode()
//		}
//	}
//}

//helper I use in stead of having a proper bootstrap method for now
func ReadServer(path string) (daga.Server, error) {
	if msg, err := read(path); err != nil {
		return nil, errors.New("ReadServer:" + err.Error())
	} else {
		if netServer, ok := msg.(*NetServer); !ok {
			return nil, errors.New("ReadServer: type assertion error, expected NetServer")
		} else {
			return netServer.NetDecode()
		}
	}
}

//helper I use in stead of having a proper bootstrap method for now
func ReadClientPrivateKey(path string) (kyber.Scalar, error) {
	if msg, err := read(path); err != nil {
		return nil, errors.New("readPrivateKey:" + err.Error())
	} else {
		if netClient, ok := msg.(*NetClient); !ok {
			return nil, errors.New("readPrivateKey: type assertion error, expected NetClient")
		} else {
			return netClient.PrivateKey, nil
		}
	}
}

func read(path string) (interface{}, error) {
	if bytes, err := ioutil.ReadFile(path); err != nil {
		return nil, err
	} else {
		if _, msg, err := network.Unmarshal(bytes, suite); err != nil {
			return nil, err
		} else {
			return msg, nil
		}
	}
}

func IndexOf(keys []kyber.Point, publicKey kyber.Point) (int, error) {
	for i, k := range keys {
		if k.Equal(publicKey) {
			return i, nil
		}
	}
	return -1, errors.New("indexOf: not in slice")
}
