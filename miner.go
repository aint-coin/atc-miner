package main

import (
	"log"
	"time"
)

type Miner struct {
	height uint64
}

func (m *Miner) start() {
	for {
		nh := getHeight()

		if m.height < nh {
			m.height = getHeight()
			log.Println(m.height)

			if m.height%10 == 0 {
				m.mine()

				time.Sleep(time.Second)

				m.mineDelete()
			} else if m.height%10 == 1 {
				m.mineIntent()
			}
		}

		time.Sleep(time.Second * MinerTick)
	}
}

func (m *Miner) mineIntent() {
	callMineIntent("3AG2sa1qeCRfBTQ3YTsBZVTz4Wz1u3YwSat", 10000)

	time.Sleep(time.Second * 10)

	callMineIntent("3AShXVgRcRis82CwD7o9pz1Ac9vmRYMqELT", 1000)

	time.Sleep(time.Second * 10)

	callMineIntent("3AKCefhcrijSwwWM671ahhMrPVrE7Je3j4s", 100)
}

func (m *Miner) mineDelete() {
	callDelete("miner__3AG2sa1qeCRfBTQ3YTsBZVTz4Wz1u3YwSat")
	callDelete("miner__3AShXVgRcRis82CwD7o9pz1Ac9vmRYMqELT")
	callDelete("miner__3AKCefhcrijSwwWM671ahhMrPVrE7Je3j4s")
}

func (m *Miner) mineExecute() {
	addr := AtcAddr
	winner, err := getData("winner", &addr)
	if err != nil {
		log.Println(err)
	}
	done := false

	log.Printf("Winner: %d", winner)

	miners := getMiners()

	for _, mnr := range miners {
		s, e := parseMiner(mnr)
		log.Printf("Start: %d End: %d", s, e)
		if s <= winner.(int64) && winner.(int64) <= e {
			done = true
			callMine(mnr.GetKey())
			log.Printf("New block: %s", mnr.GetKey())
		}
	}

	if !done {
		callMine("miner__3AG2sa1qeCRfBTQ3YTsBZVTz4Wz1u3YwSat")
	}
}

func (m *Miner) mine() {
	callWinner()

	time.Sleep(time.Second)

	m.mineExecute()
}

func initMiner() {
	m := &Miner{}
	// m.mineIntent()
	// m.mineDelete()
	// m.mineExecute()
	m.start()
}
