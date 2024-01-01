package utils

import "math/rand"

// GenerateRandomState generates the random state
func GenerateRandomState(length int) string {

	charSet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	state := make([]byte, length)

	for i := 0; i < length; i++ {
		state[i] = charSet[rand.Intn(len(charSet))]
	}

	return string(state)
}
