package protocols

import (
	"errors"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
)

// TODO share more code between the protocols, they have lots of structure/archi in common

// TODO maybe make it a method of a dagaprotocol interface etcc. (and use p.tree, p.dagaserver().index etc..) in short don't need other parameters
func NextNode(ownIndex int, Y []kyber.Point, treeNodes []*onet.TreeNode) (*onet.TreeNode, error) {
	nextServerIndex := (ownIndex + 1) % len(Y)
	nextServerPubKey := Y[nextServerIndex]
	for _, treeNode := range treeNodes {
		if treeNode.ServerIdentity.Public.Equal(nextServerPubKey) {
			return treeNode, nil
		}
	}
	return nil, errors.New("failed to find next node")
}

// TODO if when a new interface is added, add a sendToNextNode wrapper here
