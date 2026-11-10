package vless

import (
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

type Validator interface {
	Get(id uuid.UUID) *protocol.MemoryUser
	Add(u *protocol.MemoryUser) error
	Del(email string) error
	GetByEmail(email string) *protocol.MemoryUser
	GetAll() []*protocol.MemoryUser
	GetCount() int64
}

func ProcessUUID(id [16]byte) [16]byte {
	id[6] = 0
	id[7] = 0
	return id
}

// MemoryValidator stores users by the normalized UUID used for authenticated
// VLESS lookup. Bytes 6 and 7 are ignored by ProcessUUID; aliases must never
// overwrite existing users or leave inconsistent email mappings.
type MemoryValidator struct {
	mutation sync.Mutex
	email    sync.Map
	users    sync.Map
}

// Add is serialized with Del. No duplicate normalized UUID may overwrite an
// authenticated VLESS identity even when the two input UUID strings differ.
func (v *MemoryValidator) Add(u *protocol.MemoryUser) error {
	if u == nil {
		return errors.New("VLESS user is nil")
	}
	account, ok := u.Account.(*MemoryAccount)
	if !ok || account == nil || account.ID == nil {
		return errors.New("VLESS user has no valid memory account")
	}
	key := ProcessUUID(account.ID.UUID())
	email := strings.ToLower(u.Email)
	v.mutation.Lock()
	defer v.mutation.Unlock()
	if _, exists := v.users.Load(key); exists {
		return errors.New("VLESS normalized UUID already belongs to another user")
	}
	if email != "" {
		if _, exists := v.email.Load(email); exists {
			return errors.New("User ", u.Email, " already exists.")
		}
	}
	v.users.Store(key, u)
	if email != "" {
		v.email.Store(email, u)
	}
	return nil
}

// Del removes both indices atomically relative to competing Add/Del calls.
func (v *MemoryValidator) Del(e string) error {
	if e == "" {
		return errors.New("Email must not be empty.")
	}
	le := strings.ToLower(e)
	v.mutation.Lock()
	defer v.mutation.Unlock()
	raw, ok := v.email.Load(le)
	if !ok {
		return errors.New("User ", e, " not found.")
	}
	u := raw.(*protocol.MemoryUser)
	v.users.Delete(ProcessUUID(u.Account.(*MemoryAccount).ID.UUID()))
	v.email.Delete(le)
	return nil
}

// Get a VLESS user with UUID, nil if user doesn't exist.
func (v *MemoryValidator) Get(id uuid.UUID) *protocol.MemoryUser {
	u, _ := v.users.Load(ProcessUUID(id))
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// Get a VLESS user with email, nil if user doesn't exist.
func (v *MemoryValidator) GetByEmail(email string) *protocol.MemoryUser {
	email = strings.ToLower(email)
	u, _ := v.email.Load(email)
	if u != nil {
		return u.(*protocol.MemoryUser)
	}
	return nil
}

// Get all users
func (v *MemoryValidator) GetAll() []*protocol.MemoryUser {
	u := make([]*protocol.MemoryUser, 0, 100)
	v.email.Range(func(key, value interface{}) bool {
		u = append(u, value.(*protocol.MemoryUser))
		return true
	})
	return u
}

// Get users count
func (v *MemoryValidator) GetCount() int64 {
	var c int64 = 0
	v.email.Range(func(key, value interface{}) bool {
		c++
		return true
	})
	return c
}
