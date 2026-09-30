package main

// Convert the checked Ziran result at the existing Go HTTP error boundary.
func authenticationError(result AuthenticationResult) error {
	if result.Error != nil {
		return result.Error
	}
	if result.Status != 0 {
		return authError{status: result.Status, message: result.Message}
	}
	return nil
}
