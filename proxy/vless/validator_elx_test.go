package vless

import (
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
)

func testVLESSMemoryUser(id uuid.UUID, email string) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Account: &MemoryAccount{ID: protocol.NewID(id)},
		Email:   email,
	}
}

func TestMemoryValidatorNeverOverwritesNormalizedUUIDAlias(t *testing.T) {
	var validator MemoryValidator
	id := uuid.New()
	alias := id
	alias[6] ^= 0x01
	alias[7] ^= 0x80
	if id == alias || ProcessUUID(id) != ProcessUUID(alias) {
		t.Fatal("test fixture does not exercise normalized UUID collision")
	}
	original := testVLESSMemoryUser(id, "owner@example.test")
	forged := testVLESSMemoryUser(alias, "alias@example.test")
	if err := validator.Add(original); err != nil {
		t.Fatal(err)
	}
	if err := validator.Add(forged); err == nil {
		t.Fatal("a distinct-looking UUID replaced an authenticated user")
	}
	if validator.Get(id) != original || validator.Get(alias) != original ||
		validator.GetByEmail(forged.Email) != nil || validator.GetCount() != 1 {
		t.Fatal("failed alias insertion changed effective identity or left an email mapping")
	}
	if err := validator.Del(original.Email); err != nil {
		t.Fatal(err)
	}
	if err := validator.Add(forged); err != nil {
		t.Fatalf("retired identity still blocks normalized UUID reuse: %v", err)
	}
	if validator.Get(id) != forged || validator.GetCount() != 1 {
		t.Fatal("normalized UUID index disagrees with email index")
	}
}

func TestMemoryValidatorConcurrentUUIDAliasesHaveSingleWinner(t *testing.T) {
	var validator MemoryValidator
	id := uuid.New()
	alias := id
	alias[6] ^= 0x02
	candidates := []*protocol.MemoryUser{
		testVLESSMemoryUser(id, "a@example.test"),
		testVLESSMemoryUser(alias, "b@example.test"),
	}
	errs := make(chan error, len(candidates))
	var wg sync.WaitGroup
	for _, candidate := range candidates {
		wg.Add(1)
		go func(user *protocol.MemoryUser) {
			defer wg.Done()
			errs <- validator.Add(user)
		}(candidate)
	}
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		}
	}
	if success != 1 || validator.GetCount() != 1 {
		t.Fatalf("competing aliased identities both installed: successes=%d count=%d", success, validator.GetCount())
	}
	if validator.GetByEmail(candidates[0].Email) != nil &&
		validator.GetByEmail(candidates[1].Email) != nil {
		t.Fatal("both aliased email identities registered")
	}
}

func TestMemoryValidatorRejectsInvalidUser(t *testing.T) {
	var validator MemoryValidator
	if err := validator.Add(nil); err == nil {
		t.Fatal("accepted nil VLESS user")
	}
	if err := validator.Add(&protocol.MemoryUser{Email: "null@example.test"}); err == nil {
		t.Fatal("accepted missing VLESS account")
	}
}

func TestMemoryValidatorAccountsWithoutEmailStillBlockUUIDAliases(t *testing.T) {
	var validator MemoryValidator
	id := uuid.New()
	hidden := testVLESSMemoryUser(id, "")
	if err := validator.Add(hidden); err != nil {
		t.Fatal(err)
	}
	if validator.GetCount() != 1 || len(validator.GetAll()) != 1 {
		t.Fatal("active VLESS identity with empty email disappeared from inventory")
	}
	alias := id
	alias[6] ^= 1
	if err := validator.Add(testVLESSMemoryUser(alias, "new@lab")); err == nil {
		t.Fatal("effective VLESS UUID of empty-email account was overwritten")
	}
	if validator.Get(alias) != hidden || validator.GetCount() != 1 {
		t.Fatal("failed alias insertion changed live VLESS identity")
	}
}
