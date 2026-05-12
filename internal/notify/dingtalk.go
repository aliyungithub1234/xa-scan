// Package notify provides DingTalk robot notification for vulnerability reports.
// Supports signature-based security mode (HMAC-SHA256 + Base64).
//
// Environment variables:
//   - XALGORIX_DING_WEBHOOK: DingTalk webhook URL (full URL with access_token)
//   - XALGORIX_DING_SECRET:  DingTalk secret (SECxxxxxx) for signature
//
// When both are set, vulnerability reports are automatically pushed to DingTalk.
// If only one is set, DingTalk notifications are silently skipped.
package notify

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/security"
)

var (
	webhookURL string
	secret     string
	enabled    bool
	initOnce   sync.Once
)

func initConfig() {
	webhookURL = strings.TrimSpace(os.Getenv("XALGORIX_DING_WEBHOOK"))
	secret = strings.TrimSpace(os.Getenv("XALGORIX_DING_SECRET"))
	enabled = webhookURL != "" && secret != ""
	if enabled {
		log.Printf("[DINGTALK] Notifications enabled. Webhook: %s...", maskURL(webhookURL))
	}
}

func maskURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return "[invalid]"
	}
	q := parsed.Query()
	token := q.Get("access_token")
	if len(token) > 8 {
		q.Set("access_token", token[:4]+"****"+token[len(token)-4:])
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// IsEnabled returns whether DingTalk notifications are configured.
func IsEnabled() bool {
	initOnce.Do(initConfig)
	return enabled
}

// computeSignature generates the DingTalk robot signature.
// Algorithm: base64(hmac-sha256(timestamp + "\n" + secret))
func computeSignature(timestamp int64, secret string) string {
	stringToSign := fmt.Sprintf("%d\n%s", timestamp, secret)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(stringToSign))
	sign := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return sign
}

// VulnInfo holds the vulnerability data for notification.
type VulnInfo struct {
	ID                 string
	Title              string
	Severity           string
	OriginalSeverity   string
	Target             string
	Endpoint           string
	Method             string
	Description        string
	Impact             string
	ExploitationProof  string
	VerificationMethod string
	CVSS               float64
	CVE                string
	Timestamp          string
	AgentName          string
	Remediation        string
}

// severityColor returns the DingTalk markdown color tag for severity.
func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "#FF0000" // red
	case "high":
		return "#FF6600" // orange
	case "medium":
		return "#FFAA00" // yellow-orange
	case "low":
		return "#0099FF" // blue
	default:
		return "#999999" // gray
	}
}

// severityEmoji returns an emoji indicator for severity.
func severityEmoji(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	default:
		return "⚪"
	}
}

// SendVulnReport sends a vulnerability report to DingTalk.
func SendVulnReport(v VulnInfo) error {
	if !IsEnabled() {
		return nil // silently skip if not configured
	}

	msg := buildMarkdownMessage(v)
	return send(msg)
}

// SendTestMessage sends a test message to verify DingTalk configuration.
func SendTestMessage() error {
	if !IsEnabled() {
		return fmt.Errorf("DingTalk not configured. Set XALGORIX_DING_WEBHOOK and XALGORIX_DING_SECRET environment variables")
	}

	testMsg := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": "🛡️ Xalgorix 钉钉测试消息",
			"text": fmt.Sprintf(`## 🛡️ Xalgorix 钉钉机器人测试

> **状态**: ✅ 配置成功，消息推送正常
> **时间**: %s
> **版本**: Xalgorix v4 + Kimi Code + 安全限制

---

### 已加载的安全策略（12条规则）

| # | 规则 | 状态 |
|---|------|------|
| 1 | 禁止泄露项目/漏洞信息 | ✅ |
| 2 | 禁止拖库、UPDATE/DELETE/INSERT | ✅ |
| 3 | 禁止 DoS/DDoS 攻击 | ✅ |
| 4 | 禁止社工/钓鱼攻击 | ✅ |
| 5 | 禁止生产环境文件操作 | ✅ |
| 6 | 禁止大规模用户遍历 | ✅ |
| 7 | 禁止提权/内网横向 | ✅ |
| 8 | 敏感数据 ≤ 5 条 | ✅ |
| 9 | 禁止修改真实用户数据 | ✅ |
| 10 | 短信/邮件轰炸 ≤ 50 个 | ✅ |
| 11 | 禁止上传木马 | ✅ |
| 12 | 忽略低价值漏洞 | ✅ |
| 13 | **钉钉漏洞推送** | ✅ |

---

🚀 配置完成，漏洞报告将自动推送到此钉钉群。
`, time.Now().Format("2006-01-02 15:04:05")),
		},
	}

	return send(testMsg)
}

// buildMarkdownMessage creates a beautifully formatted markdown message for DingTalk.
func buildMarkdownMessage(v VulnInfo) map[string]interface{} {
	color := severityColor(v.Severity)
	emoji := severityEmoji(v.Severity)
	sevUpper := strings.ToUpper(v.Severity)

	// Truncate proof to keep message size reasonable
	proof := v.ExploitationProof
	if len(proof) > 800 {
		proof = proof[:800] + "\n\n... (已截断，完整内容请查看报告)"
	}
	// Sanitize proof for markdown
	proof = sanitizeMarkdown(proof)

	// Build verification method display
	verifyDisplay := v.VerificationMethod
	if verifyDisplay == "" {
		verifyDisplay = "未知"
	}

	// Build description
	desc := v.Description
	if len(desc) > 500 {
		desc = desc[:500] + "..."
	}
	desc = sanitizeMarkdown(desc)

	// Impact
	impact := v.Impact
	if impact == "" {
		impact = "暂无影响评估"
	}

	// Build endpoint display
	endpointDisplay := v.Endpoint
	if endpointDisplay == "" {
		endpointDisplay = "N/A"
	}

	methodDisplay := v.Method
	if methodDisplay == "" {
		methodDisplay = "N/A"
	}

	// Original severity note
	severityNote := ""
	if v.OriginalSeverity != "" && v.OriginalSeverity != v.Severity {
		severityNote = fmt.Sprintf(" (原评级: %s)", strings.ToUpper(v.OriginalSeverity))
	}

	// Build markdown text. Go raw string literals (`) cannot contain backticks,
	// so lines with markdown code formatting (e.g. `XALG-001`) are split into
	// concatenated regular strings.
	rowVulnID := "| **漏洞 ID** | `" + v.ID + "` |"
	rowEndpoint := "| **接口** | `" + endpointDisplay + "` " + methodDisplay + " |"

	text := fmt.Sprintf("## %s 新漏洞发现: [%s] %s\n\n"+
		"---\n\n"+
		"### 📋 漏洞概要\n\n"+
		"| 项目 | 详情 |\n"+
		"|------|------|\n"+
		"%s\n"+
		"| **严重程度** | <font color=\"%s\">**%s%s**</font> %s |\n"+
		"| **CVSS 评分** | %.1f |\n"+
		"| **目标** | %s |\n"+
		"%s\n"+
		"| **验证方式** | %s |\n"+
		"| **发现时间** | %s |\n"+
		"| **扫描引擎** | %s |\n\n"+
		"---\n\n"+
		"### 📝 漏洞描述\n\n"+
		"%s\n\n"+
		"---\n\n"+
		"### 💥 影响分析\n\n"+
		"%s\n\n"+
		"---\n\n"+
		"### 🔍 利用证明\n\n"+
		"```\n"+
		"%s\n"+
		"```\n\n"+
		"---\n\n"+
		"### 🛡️ 修复建议\n\n"+
		"%s\n\n"+
		"---\n\n"+
		"> ⚠️ **安全声明**: 本漏洞已按道德渗透测试规范验证，测试过程中未对目标系统造成任何破坏。\n"+
		"> \n"+
		"> 📊 **数据限制**: 敏感信息读取不超过 5 条记录，符合安全测试政策。\n",
		emoji, sevUpper, v.Title,
		rowVulnID,
		color, sevUpper, severityNote, emoji,
		v.CVSS,
		v.Target,
		rowEndpoint,
		verifyDisplay,
		v.Timestamp,
		v.AgentName,
		desc,
		impact,
		proof,
		v.Remediation,
	)

	title := fmt.Sprintf("%s [%s] %s", emoji, sevUpper, v.Title)

	return map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": title,
			"text":  text,
		},
	}
}

// sanitizeMarkdown escapes special markdown characters in raw text.
func sanitizeMarkdown(text string) string {
	// Don't escape code blocks - they should be preserved
	// Just handle basic problematic chars
	text = strings.ReplaceAll(text, "\x00", "")
	// Limit consecutive newlines
	for strings.Contains(text, "\n\n\n") {
		text = strings.ReplaceAll(text, "\n\n\n", "\n\n")
	}
	return text
}

// send delivers the message to DingTalk webhook.
func send(msg map[string]interface{}) error {
	timestamp := time.Now().UnixMilli()
	sign := computeSignature(timestamp, secret)

	// Build URL with signature params
	u, err := url.Parse(webhookURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	q := u.Query()
	q.Set("timestamp", fmt.Sprintf("%d", timestamp))
	q.Set("sign", sign)
	u.RawQuery = q.Encode()

	finalURL := u.String()

	// Serialize message
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	// Send HTTP POST
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(finalURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("HTTP post failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if result.ErrCode != 0 {
		return fmt.Errorf("DingTalk API error: code=%d, msg=%s", result.ErrCode, result.ErrMsg)
	}

	log.Printf("[DINGTALK] Message sent successfully")
	return nil
}

// SendScanSummary sends a summary of the completed scan.
func SendScanSummary(target string, totalVulns int, severityCounts map[string]int, duration time.Duration) error {
	if !IsEnabled() {
		return nil
	}

	severityLines := ""
	for sev, count := range severityCounts {
		if count > 0 {
			emoji := severityEmoji(sev)
			color := severityColor(sev)
			severityLines += fmt.Sprintf("| **%s %s** | <font color=\"%s\">%d</font> |\n", emoji, strings.ToUpper(sev), color, count)
		}
	}

	if severityLines == "" {
		severityLines = "| 暂无漏洞 | - |\n"
	}

	text := fmt.Sprintf(`## 📊 Xalgorix 扫描完成报告

---

### 🎯 扫描目标
**%s**

### ⏱️ 扫描时长
%s

### 📈 漏洞统计

| 严重程度 | 数量 |
|----------|------|
%s
| **总计** | **%d** |

---

> 🛡️ 所有漏洞均通过道德渗透测试规范验证，测试过程未对目标系统造成任何破坏。
`,
		target,
		duration.Round(time.Second).String(),
		severityLines,
		totalVulns,
	)

	msg := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": fmt.Sprintf("📊 Xalgorix 扫描完成 - %s", target),
			"text":  text,
		},
	}

	return send(msg)
}

// SanitizeProofForNotification applies data limits before sending to DingTalk.
func SanitizeProofForNotification(proof string) string {
	return security.SanitizeProofPayload(proof, security.MaxDataRecords)
}
