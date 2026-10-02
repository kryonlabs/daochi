package main

// Original native authentication error type and conversion at 258536f.
// Keep these independent of the generated type and its Error method.
type authError struct {
	status  int
	message string
}

func (e authError) Error() string {
	return e.message
}

func baselineAuthenticationError(result AuthenticationResult) error {
	if result.Error != nil {
		return result.Error
	}
	if result.Status != 0 {
		return authError{status: result.Status, message: result.Message}
	}
	return nil
}
