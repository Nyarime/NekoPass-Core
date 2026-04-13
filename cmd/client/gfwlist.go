package main

import (
	"bufio"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const gfwlistURL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

// loadGFWList 下载并解析GFWList，追加到规则
func loadGFWList() {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(gfwlistURL)
	if err != nil {
		log.Printf("[GFWList] 下载失败: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		log.Printf("[GFWList] 解码失败: %v", err)
		return
	}

	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(decoded)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		// 跳过@@白名单规则
		if strings.HasPrefix(line, "@@") {
			continue
		}
		// 提取域名
		domain := extractDomain(line)
		if domain != "" {
			rules = append(rules, Rule{Type: "DOMAIN-SUFFIX", Value: domain, Action: "PROXY"})
			count++
		}
	}
	log.Printf("[GFWList] 加载 %d 条规则", count)
}

func extractDomain(line string) string {
	// 去除前缀
	line = strings.TrimPrefix(line, "||")
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimPrefix(line, ".")
	line = strings.TrimPrefix(line, "http://")
	line = strings.TrimPrefix(line, "https://")

	// 去除路径
	if idx := strings.IndexAny(line, "/*^"); idx > 0 {
		line = line[:idx]
	}

	// 验证是域名
	if !strings.Contains(line, ".") || strings.ContainsAny(line, " @!#$%&()=+[]{}|\\<>,;:\"'") {
		return ""
	}

	return line
}
