package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"
)

const (
	numNodes       = 4
	f              = 1
	primaryNodeID  = 0
	prePrepareType = "PRE-PREPARE"
	prepareType    = "PREPARE"
	commitType     = "COMMIT"
)

type Block struct {
	Number int
	Data   string
}

type Message struct {
	Type   string
	Sender int
	Block  Block
	R, S   *big.Int
}

type Node struct {
	ID         int
	PrivKey    *ecdsa.PrivateKey
	PubKeys    map[int]*ecdsa.PublicKey
	MsgChans   map[int]chan Message
	Ledger     []Block
	PrepareSet map[string]int
	CommitSet  map[string]int
}

func (n *Node) signBlock(block Block) (*big.Int, *big.Int) {
	data := fmt.Sprintf("%d:%s", block.Number, block.Data)
	hash := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand.Reader, n.PrivKey, hash[:])
	if err != nil {
		log.Fatalf("signing failed: %v", err)
	}
	return r, s
}

func (n *Node) verifySignature(block Block, r, s *big.Int, sender int) bool {
	data := fmt.Sprintf("%d:%s", block.Number, block.Data)
	hash := sha256.Sum256([]byte(data))
	pubKey := n.PubKeys[sender]
	return ecdsa.Verify(pubKey, hash[:], r, s)
}

func (n *Node) sendMessage(receiver int, msg Message) {
	n.MsgChans[receiver] <- msg
}

func (n *Node) broadcastMessage(msg Message) {
	for id := range n.MsgChans {
		if id != n.ID {
			n.sendMessage(id, msg)
		}
	}
}

func (n *Node) run(wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case msg := <-n.MsgChans[n.ID]:
			switch msg.Type {
			case prePrepareType:
				if !n.verifySignature(msg.Block, msg.R, msg.S, msg.Sender) {
					fmt.Printf("❌ Node %d received invalid signature from %d\n", n.ID, msg.Sender)
					continue
				}
				fmt.Printf("Node %d received PRE-PREPARE from %d: Block#%d: %s\n", n.ID, msg.Sender, msg.Block.Number, msg.Block.Data)

				r, s := n.signBlock(msg.Block)
				prepareMsg := Message{
					Type:   prepareType,
					Sender: n.ID,
					Block:  msg.Block,
					R:      r,
					S:      s,
				}
				n.broadcastMessage(prepareMsg)

			case prepareType:
				if !n.verifySignature(msg.Block, msg.R, msg.S, msg.Sender) {
					fmt.Printf("❌ Node %d received invalid PREPARE from %d\n", n.ID, msg.Sender)
					continue
				}
				fmt.Printf("Node %d received PREPARE from %d\n", n.ID, msg.Sender)

				key := fmt.Sprintf("%d:%s", msg.Block.Number, msg.Block.Data)
				n.PrepareSet[key]++
				if n.PrepareSet[key] >= 2*f {
					r, s := n.signBlock(msg.Block)
					commitMsg := Message{
						Type:   commitType,
						Sender: n.ID,
						Block:  msg.Block,
						R:      r,
						S:      s,
					}
					n.broadcastMessage(commitMsg)
				}

			case commitType:
				if !n.verifySignature(msg.Block, msg.R, msg.S, msg.Sender) {
					fmt.Printf("❌ Node %d received invalid COMMIT from %d\n", n.ID, msg.Sender)
					continue
				}
				fmt.Printf("Node %d received COMMIT from %d\n", n.ID, msg.Sender)

				key := fmt.Sprintf("%d:%s", msg.Block.Number, msg.Block.Data)
				n.CommitSet[key]++
				if n.CommitSet[key] >= 2*f+1 {
					n.Ledger = append(n.Ledger, msg.Block)
					fmt.Printf("✅ Node %d committed Block#%d to ledger\n", n.ID, msg.Block.Number)
					return
				}
			}
		case <-time.After(5 * time.Second):
			fmt.Printf("⏹️ Node %d timeout\n", n.ID)
			return
		}
	}
}

func main() {
	var wg sync.WaitGroup
	nodes := make([]*Node, numNodes)
	msgChans := make(map[int]chan Message)
	pubKeys := make(map[int]*ecdsa.PublicKey)

	for i := 0; i < numNodes; i++ {
		msgChans[i] = make(chan Message, 100)
	}

	for i := 0; i < numNodes; i++ {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("key gen failed: %v", err)
		}
		pubKeys[i] = &privKey.PublicKey

		nodes[i] = &Node{
			ID:         i,
			PrivKey:    privKey,
			PubKeys:    pubKeys,
			MsgChans:   msgChans,
			PrepareSet: make(map[string]int),
			CommitSet:  make(map[string]int),
		}
	}

	for _, node := range nodes {
		wg.Add(1)
		go node.run(&wg)
	}

	block := Block{Number: 42, Data: "transfer X to Y"}
	r, s := nodes[primaryNodeID].signBlock(block)
	msg := Message{
		Type:   prePrepareType,
		Sender: primaryNodeID,
		Block:  block,
		R:      r,
		S:      s,
	}
	fmt.Printf("Node %d sending PRE-PREPARE: Block#%d: %s\n", primaryNodeID, block.Number, block.Data)
	nodes[primaryNodeID].broadcastMessage(msg)

	wg.Wait()

	fmt.Println("\n📜 Final Ledgers:")
	for _, node := range nodes {
		fmt.Printf("Node %d ledger: %+v\n", node.ID, node.Ledger)
	}
}
