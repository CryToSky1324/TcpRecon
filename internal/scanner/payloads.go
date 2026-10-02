// internal/scanner/payloads.go
package scanner

import (
	"encoding/binary"
)

// UDPPayloads maps standard UDP ports to raw byte requests designed to elicit a response.
var UDPPayloads = map[int][]byte{
	53:  BuildDNSQuery(0x1337),
	123: BuildNTPRequest(),
	// Keep 161 static until SNMP builder is implemented in Phase F.2
	// SNMP (161): SNMPv2c GetRequest for sysDescr.0
	161: []byte{
		0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70,
		0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
		0x04, 0x1a, 0x5e, 0x97, 0x00, 0x02, 0x01, 0x00,
		0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
		0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
	},
}

func BuildDNSQuery(txID uint16) []byte {
	// Memory Allocation
	buf := make([]byte, 27)

	// Header Section (12 bytes)
	binary.BigEndian.PutUint16(buf[0:2], txID)   // Bytes 0-1: Transaction ID
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // Bytes 2-3: Flags (RD = 1)
	binary.BigEndian.PutUint16(buf[4:6], 1)      // Bytes 4-5: QDCOUNT (1 question)
	// Bytes 6-11 are ANCOUNT, NSCOUNT, ARCOUNT (defaulted to 0 by make)

	// Question Section - QNAME (11 bytes)
	buf[12] = 9                   // Length of first label
	copy(buf[13:22], "localhost") // Label string content
	buf[22] = 0x00                // Null terminator of QNAME

	// QTYPE & QCLASS (4 bytes)
	binary.BigEndian.PutUint16(buf[23:25], 1) // Bytes 23-24: QTYPE (Type A)
	binary.BigEndian.PutUint16(buf[25:27], 1) // Bytes 25-26: QCLASS (Class IN)

	return buf
}

func ValidateDNSResponse(req, resp []byte) bool {
	// Minimum Buffer Lengths
	if len(resp) < 12 || len(req) < 2 {
		return false
	}

	// Transaction ID Matching
	reqID := binary.BigEndian.Uint16(req[0:2])
	respID := binary.BigEndian.Uint16(resp[0:2])
	if reqID != respID {
		return false
	}

	// Query/Response (QR) Bit Assertion
	if resp[2]&0x80 != 0x80 {
		return false
	}

	// Standard Opcode Preservation
	opcode := (resp[2] >> 3) & 0x0F
	return opcode == 0
}

func BuildNTPRequest() []byte {
	buf := make([]byte, 48)

	// RFC 5905 Byte 0 layout:
	// LI   (bits 7-6) = 00  (no leap indicator warning)
	// VN   (bits 5-3) = 100 (NTP Version 4)
	// Mode (bits 2-0) = 011 (Client Mode 3)
	// 0b00100011 == 0x23
	buf[0] = 0x23

	return buf
}

func ValidateNTPResponse(resp []byte) bool {

	// RFC 5905 48-byte length floor
	if len(resp) < 48 {
		return false
	}

	// Mode must be Server (4) or Broadcast (5)
	mode := resp[0] & 0x07
	if mode != 4 && mode != 5 {
		return false
	}

	// Version must be between 1 and 4
	vn := (resp[0] >> 3) & 0x07
	if vn < 1 || vn > 4 {
		return false
	}

	// Stratum must not exceed 16
	if resp[1] > 16 {
		return false
	}

	// Transmit Timestamp must be non-zero (Bytes 40-47)
	if binary.BigEndian.Uint64(resp[40:48]) == 0 {
		return false
	}

	return true
}
