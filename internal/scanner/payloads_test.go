package scanner

import (
	"encoding/binary"
	"testing"
)

func TestBuildDNSQuery(t *testing.T) {
	const txID = uint16(0x1337)
	buf := BuildDNSQuery(txID)

	// 1. Assert total datagram length floor & exact size
	if len(buf) != 27 {
		t.Fatalf("len(BuildDNSQuery) = %d, want 27", len(buf))
	}

	// 2. Assert Header: Transaction ID (Bytes 0-1)
	if gotID := binary.BigEndian.Uint16(buf[0:2]); gotID != txID {
		t.Errorf("txID = 0x%04x, want 0x%04x", gotID, txID)
	}

	// 3. Assert Header: Flags (Bytes 2-3) -> RD = 1 (0x0100)
	if gotFlags := binary.BigEndian.Uint16(buf[2:4]); gotFlags != 0x0100 {
		t.Errorf("flags = 0x%04x, want 0x0100", gotFlags)
	}

	// 4. Assert Header: QDCOUNT (Bytes 4-5) -> 1 Question
	if qdCount := binary.BigEndian.Uint16(buf[4:6]); qdCount != 1 {
		t.Errorf("QDCOUNT = %d, want 1", qdCount)
	}

	// 5. Assert Header: ANCOUNT, NSCOUNT, ARCOUNT are 0 (Bytes 6-11)
	for i := 6; i < 12; i++ {
		if buf[i] != 0 {
			t.Errorf("header byte %d = 0x%02x, want 0x00", i, buf[i])
		}
	}

	// 6. Assert Question: QNAME ("\x09localhost\x00")
	if buf[12] != 9 {
		t.Errorf("label length = %d, want 9", buf[12])
	}
	if gotLabel := string(buf[13:22]); gotLabel != "localhost" {
		t.Errorf("QNAME label = %q, want %q", gotLabel, "localhost")
	}
	if buf[22] != 0x00 {
		t.Errorf("QNAME null terminator = 0x%02x, want 0x00", buf[22])
	}

	// 7. Assert Question: QTYPE (Bytes 23-24) -> Type A (1)
	if qType := binary.BigEndian.Uint16(buf[23:25]); qType != 1 {
		t.Errorf("QTYPE = %d, want 1", qType)
	}

	// 8. Assert Question: QCLASS (Bytes 25-26) -> Class IN (1)
	if qClass := binary.BigEndian.Uint16(buf[25:27]); qClass != 1 {
		t.Errorf("QCLASS = %d, want 1", qClass)
	}
}

func TestValidateDNSResponse(t *testing.T) {
	req := BuildDNSQuery(0x2024)

	// Helper to forge a baseline response from the request:
	forgeResp := func() []byte {
		resp := make([]byte, len(req))
		copy(resp, req)
		resp[2] |= 0x80 // Set QR bit (Bit 7 of byte 2)
		return resp
	}

	tests := []struct {
		name string
		req  []byte
		resp []byte
		want bool
	}{
		{
			name: "Valid DNS response matching txID",
			req:  req,
			resp: forgeResp(),
			want: true,
		},
		{
			name: "Truncated response under 12-byte header floor",
			req:  req,
			resp: []byte{0x20, 0x24, 0x81, 0x80, 0x00, 0x01},
			want: false,
		},
		{
			name: "Request buffer too short to parse txID",
			req:  []byte{0x20},
			resp: forgeResp(),
			want: false,
		},
		{
			name: "Transaction ID mismatch",
			req:  req,
			resp: func() []byte {
				r := forgeResp()
				binary.BigEndian.PutUint16(r[0:2], 0x9999)
				return r
			}(),
			want: false,
		},
		{
			name: "QR bit not set (received query instead of response)",
			req:  req,
			resp: func() []byte {
				r := forgeResp()
				r[2] &^= 0x80 // Clear QR bit
				return r
			}(),
			want: false,
		},
		{
			name: "Non-standard Opcode",
			req:  req,
			resp: func() []byte {
				r := forgeResp()
				r[2] |= (0x02 << 3) // Set Status Opcode (2)
				return r
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateDNSResponse(tt.req, tt.resp)
			if got != tt.want {
				t.Errorf("ValidateDNSResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateNTPResponse(t *testing.T) {
	forgeValidNTP := func() []byte {
		b := make([]byte, 48)
		b[0] = 0x24                                              // LI=0, VN=4, Mode=4 (Server)
		b[1] = 1                                                 // Stratum 1
		binary.BigEndian.PutUint64(b[40:48], 0x1122334455667788) // Non-zero Transmit Timestamp
		return b
	}

	tests := []struct {
		name string
		resp []byte
		want bool
	}{
		{
			name: "Valid Mode 4 NTP Server response",
			resp: forgeValidNTP(),
			want: true,
		},
		{
			name: "Valid Mode 5 NTP Broadcast response",
			resp: func() []byte {
				b := forgeValidNTP()
				b[0] = (b[0] &^ 0x07) | 5 // Set Mode 5
				return b
			}(),
			want: true,
		},
		{
			name: "Datagram shorter than 48-byte floor",
			resp: make([]byte, 47),
			want: false,
		},
		{
			name: "Reflected Mode 3 Client query rejected",
			resp: func() []byte {
				b := forgeValidNTP()
				b[0] = (b[0] &^ 0x07) | 3 // Set Mode 3
				return b
			}(),
			want: false,
		},
		{
			name: "Invalid version number 0",
			resp: func() []byte {
				b := forgeValidNTP()
				b[0] = (b[0] &^ 0x38) // VN = 0
				return b
			}(),
			want: false,
		},
		{
			name: "Invalid version number greater than 4",
			resp: func() []byte {
				b := forgeValidNTP()
				b[0] = (b[0] &^ 0x38) | (5 << 3) // VN = 5
				return b
			}(),
			want: false,
		},
		{
			name: "Stratum greater than 16",
			resp: func() []byte {
				b := forgeValidNTP()
				b[1] = 17
				return b
			}(),
			want: false,
		},
		{
			name: "Transmit timestamp is all zeros",
			resp: func() []byte {
				b := forgeValidNTP()
				binary.BigEndian.PutUint64(b[40:48], 0)
				return b
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateNTPResponse(tt.resp)
			if got != tt.want {
				t.Errorf("ValidateNTPResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildNTPRequest(t *testing.T) {
	buf := BuildNTPRequest()

	// 1. RFC 5905 48-byte length requirement
	if len(buf) != 48 {
		t.Fatalf("len(BuildNTPRequest) = %d, want 48", len(buf))
	}

	// 2. RFC 5905 Byte 0: LI=0 (00b), VN=4 (100b), Mode=3 (011b) -> 0x23
	if buf[0] != 0x23 {
		t.Errorf("buf[0] = 0x%02x, want 0x23", buf[0])
	}

	// 3. Bytes 1 through 47 must be zero-filled for minimal probe
	for i := 1; i < 48; i++ {
		if buf[i] != 0x00 {
			t.Fatalf("buf[%d] = 0x%02x, want 0x00", i, buf[i])
		}
	}
}
