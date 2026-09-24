package scanner

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func ParseHTTP(conn net.Conn, timeout time.Duration) (string, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}

	probe := "GET / HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(probe)); err != nil {
		return "", err
	}

	const maxHTTPHeaderBytes = 2048
	lr := io.LimitReader(conn, maxHTTPHeaderBytes)
	reader := bufio.NewReader(lr)

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	fallbackStatus := strings.TrimRight(statusLine, "\r\n")
	bytesRead := len(statusLine)

	for {
		line, err := reader.ReadString('\n')
		bytesRead += len(line)

		if err != nil {
			if errors.Is(err, io.EOF) {
				if bytesRead >= maxHTTPHeaderBytes {
					return "", fmt.Errorf("exceeded max limit: %w", err)
				}
				break
			}
			return "", err
		}
		trimmed := strings.TrimRight(line, "\r\n")

		if trimmed == "" {
			break
		}
		lowerLine := strings.ToLower(trimmed)
		if strings.HasPrefix(lowerLine, "server:") {
			serverVal := strings.TrimSpace(trimmed[len("server:"):])
			return serverVal, nil
		}
	}
	if fallbackStatus != "" {
		return fallbackStatus, nil
	}
	return "", io.EOF
}

func ParseSSH(conn net.Conn, timeout time.Duration) (string, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	const maxBannerSize = 1024
	lr := io.LimitReader(conn, maxBannerSize)
	reader := bufio.NewReader(lr)

	line, err := reader.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			if len(line) >= maxBannerSize {
				return "", fmt.Errorf("banner exceeded max limit")
			}
			if len(line) == 0 {
				return "", err
			}
		} else {
			return "", err
		}
	}

	banner := strings.TrimRight(line, "\r\n")

	if !strings.HasPrefix(banner, "SSH-") {
		return "", fmt.Errorf("invalid protocol: not an SSH banner")
	}

	return banner, nil
}
