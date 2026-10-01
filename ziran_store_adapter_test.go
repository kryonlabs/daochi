package main

// Existing Go regression oracles still use this constructor spelling.
func OpenStore(path string) (*Store, error) {
	result := Store_Open(path)
	return result.Value, result.Error
}
