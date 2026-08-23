//go:build linux

package commands

import (
	"context"
	"errors"

	"l2syncd/internal/config"
	"l2syncd/internal/lock"
	"l2syncd/internal/preflight"
)

var saveConfig = config.Save

var errInvalidConfig = errors.New("invalid configuration")

// withConfigLocked is the authoritative config transaction primitive. The
// callback receives a freshly loaded and validated snapshot while the common
// mutation lock is held; it decides whether and when to save.
func withConfigLocked(ctx context.Context, operation func(*config.Config) error) (err error) {
	lockFile, err := lock.AcquireWait(ctx, lock.DefaultWait)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := lock.Release(lockFile); releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}()
	cfg, err := loadConfigForTransaction()
	if err != nil {
		return err
	}
	return operation(&cfg)
}

func loadConfigForTransaction() (config.Config, error) {
	cfg, err := config.Load()
	if errors.Is(err, config.ErrNotFound) {
		cfg = config.New()
		err = nil
	}
	if err != nil {
		return config.Config{}, errors.Join(errInvalidConfig, err)
	}
	if err := preflight.Validate(cfg); err != nil {
		return config.Config{}, errors.Join(errInvalidConfig, err)
	}
	return cfg, nil
}

// commitConfigLocked distinguishes an installed config from a failure before
// rename. Release and directory-fsync errors remain visible without inviting
// callers to undo state that may already be authoritative.
func commitConfigLocked(mutate func(*config.Config) error) (installed bool, err error) {
	err = withConfigLocked(context.Background(), func(cfg *config.Config) error {
		before := config.Clone(*cfg)
		if err := mutate(cfg); err != nil {
			return err
		}
		if config.Equal(before, *cfg) {
			installed = true
			return nil
		}
		saveErr := saveConfig(*cfg)
		installed = saveErr == nil || config.WasInstalled(saveErr)
		return saveErr
	})
	return installed, err
}

func updateConfigLocked(mutate func(*config.Config) error) error {
	_, err := commitConfigLocked(mutate)
	return err
}
