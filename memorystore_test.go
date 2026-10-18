package gobrowserlogin

import (
	"context"
	"sync"
	"time"
)

// memoryStore is a Store in a map, for tests of the flow above it.
type memoryStore struct {
	mu       sync.Mutex
	attempts map[Key]LoginAttempt
	sessions map[Key]Session
}

func newMemoryStore() *memoryStore {
	return &memoryStore{attempts: map[Key]LoginAttempt{}, sessions: map[Key]Session{}}
}

func (m *memoryStore) SaveLoginAttempt(_ context.Context, key Key, attempt LoginAttempt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts[key] = attempt
	return nil
}

func (m *memoryStore) TakeLoginAttempt(_ context.Context, key Key) (LoginAttempt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	attempt, ok := m.attempts[key]
	if !ok {
		return LoginAttempt{}, ErrNotFound
	}
	delete(m.attempts, key)
	return attempt, nil
}

func (m *memoryStore) SaveSession(_ context.Context, key Key, session Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[key] = session
	return nil
}

func (m *memoryStore) LoadSession(_ context.Context, key Key) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[key]
	if !ok {
		return Session{}, ErrNotFound
	}
	return session, nil
}

func (m *memoryStore) TouchSession(_ context.Context, key Key, seenAt, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session, ok := m.sessions[key]; ok {
		session.SeenAt, session.ExpiresAt = seenAt, expiresAt
		m.sessions[key] = session
	}
	return nil
}

func (m *memoryStore) DeleteSession(_ context.Context, key Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, key)
	return nil
}

func (m *memoryStore) DeleteExpired(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, attempt := range m.attempts {
		if !now.Before(attempt.ExpiresAt) {
			delete(m.attempts, key)
		}
	}
	for key, session := range m.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(m.sessions, key)
		}
	}
	return nil
}
