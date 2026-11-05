//go:build !linux

package policy

import (
	"errors"
	"os"
)

func lockPolicyFile(string) (*os.File, error) {
	return nil, errors.New("durable policy state requires Linux")
}
