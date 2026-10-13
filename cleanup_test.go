package main

// ignoreCleanupError runs a deferred cleanup, such as closing rows or rolling
// back a finished transaction, whose error a test cannot act on.
func ignoreCleanupError(cleanup func() error) {
	_ = cleanup()
}
