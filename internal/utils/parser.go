package utils

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/CryToSky1324/TcpRecon/internal/models" // Replace 'github.com/CryToSky1324/TcpRecon' with your actual go.mod module name
)

// expandCIDR mathematically generates usable IPv4 addresses from a CIDR block (Unexported/Private to utils)
func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

// incIP increments an IP address byte slice sequentially (Unexported/Private to utils)
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// IngestTargets processes a target text file line-by-line (Exported)
func IngestTargets(filePath string) models.TargetMap {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL ERROR: Cannot open target file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	targets := make(models.TargetMap)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "/") {
			ips, err := expandCIDR(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Skipping invalid CIDR %s: %v\n", line, err)
				continue
			}
			targets[line] = ips
			continue
		}

		ips, err := net.LookupIP(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Skipping unresolvable target %s: %v\n", line, err)
			continue
		}

		var validIPs []string
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				validIPs = append(validIPs, ipv4.String())
			}
		}
		if len(validIPs) > 0 {
			targets[line] = validIPs
		}
	}

	return targets
}

// ParsePortRange parses comma-separated ports and ranges (Exported)
func ParsePortRange(portStr string) ([]int, error) {
	var ports []int
	parts := strings.Split(portStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			var start, end int
			_, err := fmt.Sscanf(part, "%d-%d", &start, &end)
			if err != nil {
				return nil, fmt.Errorf("invalid port range syntax: %s", part)
			}
			for p := start; p <= end; p++ {
				if p < 1 || p > 65535 {
					return nil, fmt.Errorf("port out of range (1-65535): %d", p)
				}
				ports = append(ports, p)
			}
		} else {
			var p int
			_, err := fmt.Sscanf(part, "%d", &p)
			if err != nil {
				return nil, fmt.Errorf("invalid port syntax: %s", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range (1-65535): %d", p)
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}

// FingerprintOS analyzes application layer banners to deduce the underlying operating system (Exported)
func FingerprintOS(banner string) string {
	if banner == "" {
		return ""
	}

	normalized := strings.ToLower(banner)

	if strings.Contains(normalized, "ubuntu") {
		return "Ubuntu Linux"
	}
	if strings.Contains(normalized, "debian") {
		return "Debian Linux"
	}
	if strings.Contains(normalized, "centos") {
		return "CentOS Linux"
	}
	if strings.Contains(normalized, "freebsd") {
		return "FreeBSD"
	}
	if strings.Contains(normalized, "windows") || strings.Contains(normalized, "iis") || strings.Contains(normalized, "win32") {
		return "Microsoft Windows"
	}

	return "Unknown/Obfuscated"
}
