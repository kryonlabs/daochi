package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// maxOutstandingChallenges bounds the challenges kept for one account. The
// clients of one account, or several requests of one client, may sign in at
// the same time. Each keeps its own challenge until it is used, instead of a
// newer challenge replacing it and its login failing.
const maxOutstandingChallenges = 8

type challenge struct {
	Nonce     []byte
	ExpiresAt time.Time
}

type ChallengeStore struct {
	mu     sync.Mutex
	ttl    time.Duration
	byUser map[string][]challenge
}

func NewChallengeStore(ttl time.Duration) *ChallengeStore {
	return &ChallengeStore{ttl: ttl, byUser: make(map[string][]challenge)}
}

func (s *ChallengeStore) Issue(userID string) ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now())
	items := append(s.byUser[userID], challenge{Nonce: nonce, ExpiresAt: time.Now().Add(s.ttl)})
	if len(items) > maxOutstandingChallenges {
		items = items[len(items)-maxOutstandingChallenges:]
	}
	s.byUser[userID] = items
	return nonce, nil
}

// Outstanding returns copies of the account's unexpired challenges, newest first.
func (s *ChallengeStore) Outstanding(userID string) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	items := s.byUser[userID]
	nonces := make([][]byte, 0, len(items))
	for i := len(items) - 1; i >= 0; i-- {
		if !now.After(items[i].ExpiresAt) {
			nonces = append(nonces, append([]byte(nil), items[i].Nonce...))
		}
	}
	return nonces
}

// Take removes one challenge and reports whether it was still valid. A
// challenge that was already used or has expired is refused, so each one
// signs in at most once.
func (s *ChallengeStore) Take(userID string, nonce []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := s.byUser[userID]
	for i, item := range items {
		if !bytes.Equal(item.Nonce, nonce) {
			continue
		}
		remaining := append(append([]challenge(nil), items[:i]...), items[i+1:]...)
		if len(remaining) == 0 {
			delete(s.byUser, userID)
		} else {
			s.byUser[userID] = remaining
		}
		return !time.Now().After(item.ExpiresAt)
	}
	return false
}

// PeekBase64 shows the newest unexpired challenge without using it.
func (s *ChallengeStore) PeekBase64(userID string) (string, bool) {
	nonces := s.Outstanding(userID)
	if len(nonces) == 0 {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(nonces[0]), true
}

func (s *ChallengeStore) pruneLocked(now time.Time) {
	for userID, items := range s.byUser {
		kept := items[:0]
		for _, item := range items {
			if !now.After(item.ExpiresAt) {
				kept = append(kept, item)
			}
		}
		if len(kept) == 0 {
			delete(s.byUser, userID)
		} else {
			s.byUser[userID] = kept
		}
	}
}
