package daga_login

import (
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/onet/network"
	"io/ioutil"
)

func ReadContext(path string) (Context, error) {
	if bytes, err := ioutil.ReadFile(path); err != nil {
		return Context{}, errors.New("readContext:" + err.Error())
	} else {
		if _, msg, err := network.Unmarshal(bytes, suite); err != nil {
			return Context{}, errors.New("readContext:" + err.Error())
		} else {
			if netContext, ok := msg.(*NetContext); !ok {
				return Context{}, errors.New("readContext: type assertion error")
			} else {
				return netContext.NetDecode()
			}
		}
	}
}

func indexOf(keys []kyber.Point, publicKey kyber.Point) (int, error) {
	for i, k := range keys {
		if k.Equal(publicKey) {
			return i, nil
		}
	}
	return -1, errors.New("indexOf: not in slice")
}