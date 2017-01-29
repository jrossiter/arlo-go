package arlo

import "strconv"

func floatToHex(x float64) string {
	var result []byte
	quotient := int(x)
	fraction := x - float64(quotient)

	for quotient > 0 {
		quotient = int(x / 16)
		remainder := int(x - (float64(quotient) * 16))

		if remainder > 9 {
			result = append([]byte{byte(remainder + 55)}, result...)
		} else {
			for _, c := range strconv.Itoa(int(remainder)) {
				result = append([]byte{byte(c)}, result...)
			}
		}

		x = float64(quotient)
	}

	if fraction == 0 {
		return string(result)
	}

	result = append(result, '.')

	for fraction > 0 {
		fraction = fraction * 16
		integer := int(fraction)
		fraction = fraction - float64(integer)

		if integer > 9 {
			result = append(result, byte(integer+55))
		} else {
			for _, c := range strconv.Itoa(int(integer)) {
				result = append(result, byte(c))
			}
		}
	}

	return string(result)
}
