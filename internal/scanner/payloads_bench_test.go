package scanner

import (
	"encoding/binary"
	"testing"
)

func BenchmarkBuildDNSQuery(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildDNSQuery(0x1337)
	}
}

func BenchmarkValidateDNSResponse(b *testing.B) {
	req := BuildDNSQuery(0x1337)
	resp := make([]byte, len(req))
	copy(resp, req)
	resp[2] |= 0x80

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ValidateDNSResponse(req, resp) {
			b.Fatal("unexpected validation failure")
		}
	}
}

func BenchmarkBuildNTPRequest(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildNTPRequest()
	}
}

func BenchmarkValidateNTPResponse(b *testing.B) {
	resp := make([]byte, 48)
	resp[0] = 0x24
	resp[1] = 1
	binary.BigEndian.PutUint64(resp[40:48], 0xDEADBEEFCAFEBA99)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ValidateNTPResponse(resp) {
			b.Fatal("unexpected validation failure")
		}
	}
}
