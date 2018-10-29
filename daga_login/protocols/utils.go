package protocols

import (
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
)

// TODO maybe make it a method of a dagaprotocol interface etcc. (and use p.tree, p.dagaserver().index etc..) in short don't need other parameters
func NextNode(ownIndex int, Y []kyber.Point, treeNodes []*onet.TreeNode) *onet.TreeNode {
	nextServerIndex := (ownIndex + 1) % len(Y)
	nextServerPubKey := Y[nextServerIndex]
	for _, treeNode := range treeNodes {
		// TODO for now ok but if in future we allow nodes to have multiple daga.Server identities => doesn't work, we need sort of a directory service or protocol..
		// TODO kind of service that answer with a signature when called with a publicKey areYou(pubKey)? => {yes, sign} | { no }
		// TODO what would be a real solution to get correct treenode (if multiple daga identitities) ?
		if treeNode.ServerIdentity.Public.Equal(nextServerPubKey) {
			return treeNode
		}
	}
	return nil
}
