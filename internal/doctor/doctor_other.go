//go:build !linux && !darwin

package doctor

func platformRegistry() []registeredCheck { return nil }
