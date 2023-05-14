package unsafe

import (
	"reflect"
	"unsafe"
)

// B2S converts bs to string in an unsafe way.
//
// WARNING: The returned string shares the underlying memory with bs
// and therefore breaks Go's string immutability guarantee,
// it shall only be used for temporary conversions with caution!
func B2S(bs []byte) string {
	return *(*string)(unsafe.Pointer(&bs))
}

// S2B converts s to []byte in an unsafe way.
//
// WARNING: The returned byte slice shares the underlying memory with s
// and therefore breaks Go's string immutability guarantee,
// it shall only be used for temporary conversions with caution!
func S2B(s string) []byte {
	return (*[0x7fff0000]byte)(unsafe.Pointer(
		(*reflect.StringHeader)(unsafe.Pointer(&s)).Data),
	)[:len(s):len(s)]
}
