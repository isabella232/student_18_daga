package daga_login

import (
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/onet/network"
	"github.com/dedis/student_18_daga/sign/daga"
	"io/ioutil"
)

//helper I use in stead of having a proper bootstrap method for now
func ReadContext(path string) (Context, error) {
	if msg, err := read(path); err != nil {
		return Context{}, errors.New("readContext:" + err.Error())
	} else {
		if netContext, ok := msg.(*NetContext); !ok {
			return Context{}, errors.New("readContext: type assertion error, expected NetContext")
		} else {
			return netContext.NetDecode()
		}
	}
}

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
