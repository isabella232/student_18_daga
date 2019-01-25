package protocols

import (
	"errors"
	"github.com/dedis/onet"
	"go.dedis.ch/kyber"
)

// NextNode returns the node right after us (ownIndex) in the ring.
// (that start at leader and whose order is based on indices in the slice of keys).
// i.e. the tree node whose key is equal to keys[(ownIndex + 1) % len(keys)]
// TODO share more code between the protocols, they have lots of structure/archi in common
// TODO if when a new interface is added, add a sendToNextNode wrapper here
// TODO maybe make it a method of a dagaprotocol interface etcc. (and use p.tree, p.dagaserver().index etc..) in short don't need other parameters
func NextNode(ownIndex int, keys []kyber.Point, treeNodes []*onet.TreeNode) (*onet.TreeNode, error) {
	nextServerIndex := (ownIndex + 1) % len(keys)
	nextServerPubKey := keys[nextServerIndex]
	for _, treeNode := range treeNodes {
		if treeNode.ServerIdentity.Public.Equal(nextServerPubKey) {
			return treeNode, nil
		}
	}
	return nil, errors.New("failed to find next node")
}
