package webrtc

import (
	"context"
	"github.com/pion/stun"
	"sync"
	"time"
)

const (
	STUN_REQ_TTL_SECS                 = 5
	STUN_DELETE_EXPIRED_INTERVAL_SECS = 10
)

type StunTransactionsMap struct {
	sync.RWMutex
	Data map[string]*stunTTL
}

type stunTTL struct {
	message *stun.Message
	ttl     time.Time
}

func NewStunTransactionsMap(ctx context.Context) *StunTransactionsMap {
	m := new(StunTransactionsMap)
	m.Data = make(map[string]*stunTTL)

	// clean expired entries periodically
	ticker := time.NewTicker(time.Second * STUN_DELETE_EXPIRED_INTERVAL_SECS)
	go func() {
		for {
			select {
			case <-ticker.C:
				m.DeleteExpired()
			case <-ctx.Done():
				return
			}
		}
	}()

	return m
}

func (stm *StunTransactionsMap) Add(message *stun.Message) {
	stm.Lock()
	defer stm.Unlock()
	ttl := &stunTTL{
		message: message,
		ttl:     time.Now().Add(time.Second * STUN_REQ_TTL_SECS),
	}

	stm.Data[string(message.TransactionID[:])] = ttl
}

func (stm *StunTransactionsMap) Get(key string) (message *stun.Message) {
	stm.RLock()
	defer stm.RUnlock()
	s := stm.Data[key]
	if s != nil {
		return s.message
	}
	return
}

func (stm *StunTransactionsMap) Delete(key string) {
	stm.Lock()
	defer stm.Unlock()
	delete(stm.Data, key)
}

func (stm *StunTransactionsMap) DeleteExpired() {
	stm.Lock()
	defer stm.Unlock()
	now := time.Now()
	for key, stunRequest := range stm.Data {
		if stunRequest.ttl.Before(now) {
			delete(stm.Data, key)
		}
	}
	return
}
