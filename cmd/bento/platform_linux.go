package main

// checkPlatform passes on Linux, the one host bento enforces on.
//
// A variable rather than a function, and only here: run, profile and doctor each raise
// the refusal inside their own RunE, where a check that returns nil on the only host the
// tests run on is otherwise unobservable - deleting the call from one of them would break
// nothing any gate catches. Swapping this lets a test watch each command answer a host
// with no backend in its own shape. The non-Linux definition stays a plain function,
// since the host that must refuse is the one nothing may talk out of refusing.
var checkPlatform = func() error { return nil }
