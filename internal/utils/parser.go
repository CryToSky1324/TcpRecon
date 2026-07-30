package utils

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CryToSky1324/TcpRecon/internal/models" // Replace 'github.com/CryToSky1324/TcpRecon' with your actual go.mod module name
)

// FetchTargets streams the target list from an external HTTP/S3 endpoint.
func FetchTargets(ctx context.Context, targetURL string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("target fetch failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	return resp.Body, nil
}

// StreamTargets reads line-by-line, preventing heap exhaustion, and feeds the worker channel.
func StreamTargets(ctx context.Context, r io.Reader, tcpPorts []int, udpPorts []int, rawJobs chan<- models.ScanJob) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "/") {
			ips, err := expandCIDR(line)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				dispatchJobs(ctx, ip, line, tcpPorts, udpPorts, rawJobs)
			}
			continue
		}

		ips, err := net.LookupIP(line)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			dispatchJobs(ctx, ip.String(), line, tcpPorts, udpPorts, rawJobs)
		}
	}
}

// dispatchJobs pushes the generated structs into the routing channel with explicit protocol tags
func dispatchJobs(ctx context.Context, ip string, targetName string, tcpPorts []int, udpPorts []int, rawJobs chan<- models.ScanJob) {
	// 1. Dispatch TCP Vectors
	for _, port := range tcpPorts {
		select {
		case <-ctx.Done():
			return
		case rawJobs <- models.ScanJob{TargetIP: ip, TargetName: targetName, Port: port, Protocol: "tcp"}:
		}
	}

	// 2. Dispatch UDP Vectors
	for _, port := range udpPorts {
		select {
		case <-ctx.Done():
			return
		case rawJobs <- models.ScanJob{TargetIP: ip, TargetName: targetName, Port: port, Protocol: "udp"}:
		}
	}
}

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

// ParsePortRange parses comma-separated ports and ranges (Exported)
func ParsePortRange(portStr string) ([]int, error) {
	var ports []int
	parts := strings.Split(portStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range syntax: %s", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range syntax: %s", part)
			}
			end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil || start > end {
				return nil, fmt.Errorf("invalid port range syntax: %s", part)
			}
			for p := start; p <= end; p++ {
				if p < 1 || p > 65535 {
					return nil, fmt.Errorf("port out of range (1-65535): %d", p)
				}
				ports = append(ports, p)
			}
		} else {
			p, err := strconv.Atoi(part)
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
