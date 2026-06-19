package main

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type challenge struct {
	Nonce     []byte
	ExpiresAt time.Time
}

type ChallengeStore struct {
	mu     sync.Mutex
	ttl    time.Duration
	byUser map[string]challenge
}

func NewChallengeStore(ttl time.Duration) *ChallengeStore {
	return &ChallengeStore{ttl: ttl, byUser: make(map[string]challenge)}
}

func (s *ChallengeStore) Issue(userID string) ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now())
	s.byUser[userID] = challenge{Nonce: nonce, ExpiresAt: time.Now().Add(s.ttl)}
	return nonce, nil
}

func (s *ChallengeStore) Consume(userID string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.byUser[userID]
	if !ok {
		return nil, false
	}
	delete(s.byUser, userID)
	if time.Now().After(item.ExpiresAt) {
		return nil, false
	}
	return item.Nonce, true
}

func (s *ChallengeStore) PeekBase64(userID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.byUser[userID]
	if !ok || time.Now().After(item.ExpiresAt) {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(item.Nonce), true
}

func (s *ChallengeStore) pruneLocked(now time.Time) {
	for userID, item := range s.byUser {
		if now.After(item.ExpiresAt) {
			delete(s.byUser, userID)
		}
	}
}
