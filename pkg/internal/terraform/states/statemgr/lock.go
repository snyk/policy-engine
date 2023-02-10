package statemgr

import (
	"github.com/snyk/policy-engine/pkg/internal/terraform/states"
	"github.com/snyk/policy-engine/pkg/internal/terraform/terraform"
)

// LockDisabled implements State and Locker but disables state locking.
// If State doesn't support locking, this is a no-op. This is useful for
// easily disabling locking of an existing state or for tests.
type LockDisabled struct {
	// We can't embed State directly since Go dislikes that a field is
	// State and State interface has a method State
	Inner Full
}

func (s *LockDisabled) State() *states.State {
	return s.Inner.State()
}

func (s *LockDisabled) GetRootOutputValues() (map[string]*states.OutputValue, error) {
	return s.Inner.GetRootOutputValues()
}

func (s *LockDisabled) WriteState(v *states.State) error {
	return s.Inner.WriteState(v)
}

func (s *LockDisabled) RefreshState() error {
	return s.Inner.RefreshState()
}

func (s *LockDisabled) PersistState(schemas *terraform.Schemas) error {
	return s.Inner.PersistState(schemas)
}

func (s *LockDisabled) Lock(info *LockInfo) (string, error) {
	return "", nil
}

func (s *LockDisabled) Unlock(id string) error {
	return nil
}
