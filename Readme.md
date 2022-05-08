# Merkle - Efficient calculation of merkle roots and proofs

[![Go Reference](https://pkg.go.dev/badge/github.com/bobg/merkle.svg)](https://pkg.go.dev/github.com/bobg/merkle)
[![Go Report Card](https://goreportcard.com/badge/github.com/bobg/merkle)](https://goreportcard.com/report/github.com/bobg/merkle)
[![Tests](https://github.com/bobg/merkle/actions/workflows/go.yml/badge.svg)](https://github.com/bobg/merkle/actions/workflows/go.yml)
[![Coverage Status](https://coveralls.io/repos/github/bobg/merkle/badge.svg?branch=master)](https://coveralls.io/github/bobg/merkle?branch=master)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/avelino/awesome-go)

This is merkle,
a Go package for computing the Merkle root hash of a sequence of byte strings,
or of their hashes.
It can also produce a compact proof that a given string belongs in a Merkle tree with a given root hash.

This implementation does not require holding all of the input in memory while computing a root hash or a proof.
Instead, it is able to operate on a stream of input strings of unbounded length,
holding incremental state that is only logarithmic [O(log N)] in the size of the input.

For more about Merkle trees,
see [the Wikipedia article](https://en.wikipedia.org/wiki/Merkle_tree).

Creating a merkle root hash:

```go
var ch <-chan []byte  // Represents some source of byte strings
tree := merkle.NewTree(sha256.New())
for str := range ch {
  tree.Add(str)
}
fmt.Printf("merkle root hash is %x\n", tree.Root())
```

Creating a merkle proof that `ref` belongs in the tree,
then verifying the proof:

```go
var (
  ch       <-chan []byte  // Represents some source of byte strings
  rootHash []byte         // Represents a previously computed merkle root hash (held by someone wishing to verify that ref is in the tree)
  ref      []byte         // Represents the string to prove is a member of the tree with the given root hash
)
tree := merkle.NewProofTree(sha256.New(), ref)
for str := range ch {
  tree.Add(str)
}
proof := tree.Proof()  // This is a compact object. For verification purposes, tree can now be discarded.

// Verification:
if bytes.Equal(rootHash, proof.Hash(sha256.New(), ref)) {
  fmt.Println("Verified!")
}
```
