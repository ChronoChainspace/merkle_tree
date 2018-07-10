/*
 * Author: Andrew Bryzgalov
 * Email: bryzgalovandrew@gmail.com
 * Site: http://chronochain.space
 */

package merkle

import (
	"fmt"
)

// PoE
type ProofOfExistence struct {
	ReverseHash [][]byte
	BranchPos 	uint32
}


type MerkleHash func(input ...[]byte) []byte

/*
	Merkle Tree Height < 32, that can hold up to 2^31 leaf nodes;
Parameters:
	@leftlist : The leaf node queue, which contains the hash value;
	@branchpos : Leaf node number, if you want to get PoE need to pass, otherwise set to 0;
	@pBranch ： Reverse hash queue, if you want to get PoE need to pass, otherwise set to nil;
	@Hash ： Generate the hash algorithm of MerkleRootHash;
Return value
	merkle-tree root hash and error messages.
*/
func MerkleTreeRootHash(leftlist [][]byte, branchpos uint32, pBranch *[][]byte, Hash MerkleHash)([]byte,error) {
	var h,root []byte
	var inner [32][]byte

	isMatched := false
	count  := uint32(0)
	level  := uint32(0)
	matchlevel := uint32(0xFFFFFFFF)


	if(len(leftlist) == 0){
		return root, fmt.Errorf("the lable list cannot be empty!!!")
	}

	if(branchpos >= uint32(len(leftlist))){
		return root, fmt.Errorf("the pos is out of range")
	}

	for _, left := range leftlist{
		h = left[:]
		isMatched = (count==branchpos)
		count++

		level =0
		for ;(count & (1<<level)) == 0;{
			if(pBranch != nil){
				if(isMatched){
					*pBranch = append(*pBranch, inner[level])
				}else if(matchlevel == level){
					*pBranch = append(*pBranch, h)
					isMatched = true
				}
			}

			h = Hash(inner[level], h)
			level++
		}

		inner[level] = h
		if(isMatched){
			matchlevel = level
		}
	}

	level  = 0
	for ; (count&(1<<level)) == 0;{
		level++
	}


	h = inner[level][:]
	isMatched = (matchlevel == level)
	for ;count != (1 << level);{
		if(pBranch != nil && isMatched){
			*pBranch = append(*pBranch, h)
		}

		h = Hash(h, h)
		count += (1<<level)
		level++

		for ;(count & (1<<level)) == 0;{
			if(pBranch != nil){
				if(isMatched){
					*pBranch = append(*pBranch, inner[level]);
				}else if(matchlevel == level) {
					*pBranch = append(*pBranch, h)
					isMatched = true
				}
			}

			h = Hash(inner[level], h)
			level++
		}
	}

	root = h[:]
	return root, nil
}

/*
Verify that the Reversehash in the proof of existence is legal
Parameters
	@rootHash: root hash of merkle Tree;
	@pfExistence： left proof of existence;
	@left: Leaf nodes;
	@branchPos: Leaf node number;
	@Hash： Custom hash functions must be consistent with the hash function that generates the POE
Return value
	Correct/failure and error messages
*/
func CheckLeftWithPOE(rootHash []byte,  existence *ProofOfExistence, left []byte, Hash MerkleHash) (bool, error){
	if(existence == nil){
		return false, fmt.Errorf("the proof of Existence is nil")
	}

	if(len(existence.ReverseHash)==0 ){
		return false, fmt.Errorf("the proof of Existenc is empty")
	}

	if(len(existence.ReverseHash) >= 32){
		return false, fmt.Errorf("the tree heigth is over range")
	}

	if(existence.BranchPos > uint32(2<< uint8(len(existence.ReverseHash)))){
		return false, fmt.Errorf("the Branpos %d is over range !!!", existence.BranchPos)
	}

	h := left;
	branchPos := existence.BranchPos

	for _, reverseHash := range (existence.ReverseHash){
		if(branchPos%2 == 1 ){
			h = Hash(reverseHash, h)
		}else {
			h = Hash(h, reverseHash)
		}

		branchPos/=2
	}

	for i :=0; i < 32 ; i++ {
		if(h[i] != rootHash[i]){
			return false, fmt.Errorf("the proof of Existence is wrong!")
		}
	}

	return true, nil
}