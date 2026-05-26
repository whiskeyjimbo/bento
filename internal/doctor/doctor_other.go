//go:build !linux && !darwin

package doctor

func platformRegistry(_ *config) []registeredCheck { return nil }
