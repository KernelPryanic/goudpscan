package unsafe

import "unsafe"

// B2S unsafely converts b to string.
//
// WARNING: The returned string shares the underlying memory with b
// and therefore breaks Go's string immutability guarantee.
// Use for temporary conversions with utmost caution!
func B2S(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// S2B unsafely converts s to []byte.
//
// WARNING: The returned byte slice shares the underlying memory with s
// and therefore breaks Go's string immutability guarantee.
// Use for temporary conversions with utmost caution!
func S2B(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
