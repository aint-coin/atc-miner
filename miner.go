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
				log.Println("New block!")
			}
		}

		time.Sleep(time.Second * MinerTick)
	}
}

func (m *Miner) mine() {
	callMineIntent("3AG2sa1qeCRfBTQ3YTsBZVTz4Wz1u3YwSat")

	time.Sleep(time.Second * 10)

	callWinner()

	time.Sleep(time.Second)

	callMine("miner__3AG2sa1qeCRfBTQ3YTsBZVTz4Wz1u3YwSat")

	time.Sleep(time.Second)

	callDelete("miner__3AG2sa1qeCRfBTQ3YTsBZVTz4Wz1u3YwSat")
}

func initMiner() {
	m := &Miner{}
	m.start()
}
