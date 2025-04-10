package helpers

import "math"

func ByteToBitsInt(b []byte) []uint {
	bits := []uint{}
	for _, byteq := range b {

		for i := 7; i >= 0; i-- {
			if (byteq>>i)&1 == 1 {
				bits = append(bits, 1)
			} else {
				bits = append(bits, 0)
			}
		}
	}
	return bits
}

func BinaryUintToInt(bits []uint) int {
	result := 0
	power := 0
	for i := len(bits) - 1; i >= 0; i-- {
		if bits[i] == 1 {
			result += int(math.Pow(2, float64(power)))
		}
		power++
	}
	return result
}
