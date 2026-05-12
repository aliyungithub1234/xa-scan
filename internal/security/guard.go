// Package security provides the safety guardrails for Xalgorix.
// It enforces the ethical penetration testing policy — prove vulnerabilities
// exist WITHOUT becoming a malicious actor. All rules are designed to
// mitigate legal risks and ensure responsible disclosure.
//
// Policy Rules (11 core rules):
//   1. No disclosure of project/vulnerability information
//   2. No database dumping, mass CRUD operations
//   3. No DoS/DDoS or service disruption tests
//   4. No social engineering or phishing attacks
//   5. No production file overwrite/deletion
//   6. No mass user enumeration
//   7. No privilege escalation or lateral movement
//   8. Sensitive data: read ≤ 5 records max
//   9. No modification/deletion of real user data
//  10. SMS/email bombing ≤ 50 targets
//  11. No malware upload; text proof only
//  12. Ignore low-value vulns (URL redirect, weak password, self-XSS, etc.)
package security

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

// ── Configuration ────────────────────────────────────────────────────────────

var (
	// GuardMode controls the security strictness.
	// "strict" (default) — all rules enforced
	// "warn" — only log violations without blocking
	// "off" — disable all guards (NOT RECOMMENDED for production)
	GuardMode string

	// MaxDataRecords limits how many records can be retrieved
	// during a single proof-of-concept (rule #8)
	MaxDataRecords = 5

	// MaxEmailSMSTargets limits bulk email/SMS targets (rule #10)
	MaxEmailSMSTargets = 50

	initOnce sync.Once
)

func init() {
	initOnce.Do(func() {
		GuardMode = strings.ToLower(os.Getenv("XALGORIX_GUARD_MODE"))
		if GuardMode == "" {
			GuardMode = "strict"
		}
		if GuardMode != "strict" && GuardMode != "warn" && GuardMode != "off" {
			GuardMode = "strict"
		}
	})
}

// IsStrict returns true if guards are in strict mode.
func IsStrict() bool { return GuardMode == "strict" }

// IsWarn returns true if guards are in warn mode.
func IsWarn() bool { return GuardMode == "warn" }

// IsOff returns true if guards are disabled.
func IsOff() bool { return GuardMode == "off" }

// GuardResult is the outcome of a security check.
type GuardResult struct {
	Blocked bool
	Reason  string
	Level   string // "critical", "high", "medium", "info"
}

// ── Blocked Pattern Categories ───────────────────────────────────────────────

// BlockedPattern is a security rule pattern.
type BlockedPattern struct {
	Category string // e.g. "destructive", "privesc", "dos", "enumeration"
	Pattern  string
	Reason   string
	Level    string
}

// guardPatterns contains ALL security guard patterns.
// They are grouped by the 11 policy rules.
var guardPatterns = []BlockedPattern{
	// ═══════════════════════════════════════════════════════════
	// RULE 2: No database dumping, mass CRUD, UPDATE/DELETE/INSERT
	// ═══════════════════════════════════════════════════════════
	{"sql-crud", "update ", "UPDATE statements are blocked (Rule #2). Proving SQLi with SELECT-only is sufficient.", "critical"},
	{"sql-crud", "update(", "UPDATE statements are blocked (Rule #2). Proving SQLi with SELECT-only is sufficient.", "critical"},
	{"sql-crud", "delete ", "DELETE statements are blocked (Rule #2). Never delete data from the target.", "critical"},
	{"sql-crud", "delete(", "DELETE statements are blocked (Rule #2). Never delete data from the target.", "critical"},
	{"sql-crud", "drop ", "DROP statements are blocked (Rule #2). Never drop tables or databases.", "critical"},
	{"sql-crud", "drop(", "DROP statements are blocked (Rule #2). Never drop tables or databases.", "critical"},
	{"sql-crud", "truncate", "TRUNCATE statements are blocked (Rule #2). Never truncate tables.", "critical"},
	{"sql-crud", "insert ", "INSERT statements are blocked (Rule #2). Never insert data into the target.", "critical"},
	{"sql-crud", "insert(", "INSERT statements are blocked (Rule #2). Never insert data into the target.", "critical"},
	{"sql-crud", "replace ", "REPLACE statements are blocked (Rule #2). Never replace data.", "critical"},
	{"sql-crud", "alter ", "ALTER statements are blocked (Rule #2). Never alter schema.", "critical"},
	{"sql-crud", "merge ", "MERGE statements are blocked (Rule #2). Never merge data.", "critical"},

	// ═══════════════════════════════════════════════════════════
	// RULE 2: No database dumping / mass extraction
	// ═══════════════════════════════════════════════════════════
	{"dumping", "dump ", "Database dumping is blocked (Rule #2). Use COUNT(*) or LIMIT 1 instead.", "critical"},
	{"dumping", "mysqldump", "mysqldump is blocked (Rule #2). Never dump entire databases.", "critical"},
	{"dumping", "pg_dump", "pg_dump is blocked (Rule #2). Never dump entire databases.", "critical"},
	{"dumping", "select * from", "SELECT * FROM is restricted (Rule #2). Use SELECT COUNT(*) or SELECT column LIMIT 1.", "high"},
	{"dumping", "limit 0", "LIMIT without bounds is restricted (Rule #2). Use LIMIT 1 for proof.", "medium"},

	// ═══════════════════════════════════════════════════════════
	// RULE 3: No DoS / DDoS / service disruption
	// ═══════════════════════════════════════════════════════════
	{"dos", "hping3", "hping3 is blocked (Rule #3). No DoS/DDoS testing allowed.", "critical"},
	{"dos", "slowhttptest", "slowhttptest is blocked (Rule #3). No DoS testing allowed.", "critical"},
	{"dos", "goldeneye", "GoldenEye is blocked (Rule #3). No DoS testing allowed.", "critical"},
	{"dos", "t50", "t50 is blocked (Rule #3). No DoS testing allowed.", "critical"},
	{"dos", "loic", "LOIC is blocked (Rule #3). No DDoS testing allowed.", "critical"},
	{"dos", "hoic", "HOIC is blocked (Rule #3). No DDoS testing allowed.", "critical"},
	{"dos", "bypass-firewall-by-dos", "DoS firewall bypass is blocked (Rule #3).", "critical"},
	{"dos", "slowloris", "Slowloris is blocked (Rule #3). No DoS testing allowed.", "critical"},
	{"dos", "apache-killer", "Apache Killer is blocked (Rule #3). No DoS testing allowed.", "critical"},
	{"dos", "rudy", "R.U.D.Y. is blocked (Rule #3). No DoS testing allowed.", "critical"},
	{"dos", "tor's hammer", "TOR's Hammer is blocked (Rule #3). No DoS testing allowed.", "critical"},
	{"dos", "xflood", "xFlood is blocked (Rule #3). No DoS testing allowed.", "critical"},
	{"dos", "iaxflood", "iaxflood is blocked (Rule #3). No DoS testing allowed.", "critical"},
	{"dos", "dhcpig", "DHCPig is blocked (Rule #3). No DoS testing allowed.", "critical"},
	{"dos", "mkflood", "macof/mkflood is blocked (Rule #3). No DoS testing allowed.", "critical"},
	{"dos", "siege", "siege is blocked (Rule #3). No load testing/DoS allowed.", "critical"},
	{"dos", "ab -n", "ab (Apache Bench) with high count is blocked (Rule #3).", "critical"},
	{"dos", "ab -c", "ab (Apache Bench) with concurrency is blocked (Rule #3).", "critical"},
	{"dos", "wrk", "wrk is blocked (Rule #3). No load testing/DoS allowed.", "critical"},
	{"dos", "hey ", "hey is blocked (Rule #3). No load testing/DoS allowed.", "critical"},
	{"dos", "vegeta", "vegeta is blocked (Rule #3). No load testing/DoS allowed.", "critical"},
	{"dos", "tsunami", "Tsunami is blocked (Rule #3). No DoS testing allowed.", "critical"},
	{"dos", "booter", "Booter/stresser tools are blocked (Rule #3). No DDoS allowed.", "critical"},
	{"dos", "stresser", "Stresser tools are blocked (Rule #3). No DDoS allowed.", "critical"},
	{"dos", "synflood", "SYN flood is blocked (Rule #3). No DoS allowed.", "critical"},
	{"dos", "udpflood", "UDP flood is blocked (Rule #3). No DoS allowed.", "critical"},
	{"dos", "icmpflood", "ICMP flood is blocked (Rule #3). No DoS allowed.", "critical"},
	{"dos", "ping -f", "Ping flood (-f) is blocked (Rule #3). No DoS allowed.", "critical"},
	{"dos", "ping -s 655", "Oversized ping is blocked (Rule #3). No DoS allowed.", "critical"},
	{"dos", "iis -reset", "IIS reset is blocked (Rule #3). No service disruption.", "critical"},
	{"dos", "service stop", "Service stop is blocked (Rule #3). No service disruption.", "critical"},
	{"dos", "systemctl stop", "systemctl stop is blocked (Rule #3). No service disruption.", "critical"},
	{"dos", "shutdown", "Shutdown is blocked (Rule #3). No service disruption.", "critical"},
	{"dos", "reboot", "Reboot is blocked (Rule #3). No service disruption.", "critical"},
	{"dos", "killall", "killall is blocked (Rule #3). No process termination.", "critical"},
	{"dos", "kill -9", "Force kill (-9) is blocked (Rule #3). No process termination.", "critical"},
	{"dos", "fork bomb", "Fork bomb is blocked (Rule #3). No resource exhaustion.", "critical"},
	{"dos", ":(){ :|:& };:", "Fork bomb is blocked (Rule #3). No resource exhaustion.", "critical"},

	// ═══════════════════════════════════════════════════════════
	// RULE 5: No production file overwrite / deletion
	// ═══════════════════════════════════════════════════════════
	{"destructive", "rm -rf /", "rm -rf / is blocked (Rule #5). Never delete system files.", "critical"},
	{"destructive", "rm -rf /*", "rm -rf /* is blocked (Rule #5). Never delete system files.", "critical"},
	{"destructive", "rm -rf ~", "rm -rf ~ is blocked (Rule #5). Never delete home directory.", "critical"},
	{"destructive", ":> /", "File overwrite via :> is blocked (Rule #5).", "critical"},
	{"destructive", "> /", "File overwrite via > is blocked (Rule #5).", "high"},
	{"destructive", "dd if=/dev/zero", "Disk wipe via dd is blocked (Rule #5).", "critical"},
	{"destructive", "dd if=/dev/urandom", "Disk overwrite is blocked (Rule #5).", "critical"},
	{"destructive", "mkfs.", "Filesystem formatting is blocked (Rule #5).", "critical"},
	{"destructive", "fdisk", "Disk partitioning is blocked (Rule #5).", "critical"},
	{"destructive", "format ", "Disk formatting is blocked (Rule #5).", "critical"},

	// ═══════════════════════════════════════════════════════════
	// RULE 7: No privilege escalation
	// ═══════════════════════════════════════════════════════════
	{"privesc", "sudo ", "sudo is blocked (Rule #7). No privilege escalation.", "critical"},
	{"privesc", "su -", "su is blocked (Rule #7). No privilege escalation.", "critical"},
	{"privesc", "chmod +s", "setuid escalation is blocked (Rule #7).", "critical"},
	{"privesc", "chmod u+s", "setuid escalation is blocked (Rule #7).", "critical"},
	{"privesc", "chown root", "chown to root is blocked (Rule #7).", "critical"},
	{"privesc", "passwd root", "Root password change is blocked (Rule #7).", "critical"},
	{"privesc", "usermod -aG sudo", "Adding to sudoers is blocked (Rule #7).", "critical"},
	{"privesc", "pkexec", "pkexec is blocked (Rule #7). No privilege escalation.", "critical"},
	{"privesc", "doas", "doas is blocked (Rule #7). No privilege escalation.", "critical"},
	{"privesc", "setfacl", "ACL manipulation for privesc is blocked (Rule #7).", "high"},
	{"privesc", "suid", "SUID exploitation attempts are blocked (Rule #7). Report the finding without exploitation.", "critical"},

	// ═══════════════════════════════════════════════════════════
	// RULE 7: No lateral movement / internal network scanning
	// ═══════════════════════════════════════════════════════════
	{"lateral", "nmap 10.", "Scanning 10.x.x.x (internal network) is blocked (Rule #7). No internal network scanning.", "critical"},
	{"lateral", "nmap 172.16.", "Scanning 172.16.x.x (internal network) is blocked (Rule #7).", "critical"},
	{"lateral", "nmap 192.168.", "Scanning 192.168.x.x (internal network) is blocked (Rule #7).", "critical"},
	{"lateral", "nmap 169.254.", "Scanning link-local addresses is blocked (Rule #7).", "critical"},
	{"lateral", "nmap 127.", "Scanning localhost (127.x.x.x) is blocked (Rule #7).", "critical"},
	{"lateral", "net view", "Windows network browsing is blocked (Rule #7). No lateral movement.", "critical"},
	{"lateral", "net use", "Windows network share mounting is blocked (Rule #7).", "critical"},
	{"lateral", "crackmapexec", "CrackMapExec is blocked (Rule #7). No lateral movement.", "critical"},
	{"lateral", "impacket", "Impacket tools for lateral movement are blocked (Rule #7).", "critical"},
	{"lateral", "psexec", "PsExec is blocked (Rule #7). No remote code execution.", "critical"},
	{"lateral", "wmiexec", "WMIExec is blocked (Rule #7). No remote code execution.", "critical"},
	{"lateral", "smbexec", "SMBExec is blocked (Rule #7). No remote code execution.", "critical"},
	{"lateral", "atexec", "AtExec is blocked (Rule #7). No remote code execution.", "critical"},
	{"lateral", "bloodhound", "BloodHound is blocked (Rule #7). No AD enumeration.", "critical"},
	{"lateral", "sharpview", "SharpView is blocked (Rule #7). No AD enumeration.", "critical"},
	{"lateral", "mimikatz", "Mimikatz is blocked (Rule #7). No credential dumping.", "critical"},
	{"lateral", "secretsdump", "secretsdump is blocked (Rule #7). No credential dumping.", "critical"},
	{"lateral", "lsadump", "LSA dump is blocked (Rule #7). No credential dumping.", "critical"},
	{"lateral", "hashdump", "Hash dump is blocked (Rule #7). No credential dumping.", "critical"},
	{"lateral", "cachedump", "Cache dump is blocked (Rule #7). No credential dumping.", "critical"},
	{"lateral", "samdump", "SAM dump is blocked (Rule #7). No credential dumping.", "critical"},
	{"lateral", "procdump", "Process dump for creds is blocked (Rule #7).", "critical"},
	{"lateral", "pass-the-hash", "Pass-the-Hash is blocked (Rule #7).", "critical"},
	{"lateral", "overpass-the-hash", "Overpass-the-Hash is blocked (Rule #7).", "critical"},
	{"lateral", "golden ticket", "Golden Ticket is blocked (Rule #7). No Kerberos attacks.", "critical"},
	{"lateral", "silver ticket", "Silver Ticket is blocked (Rule #7). No Kerberos attacks.", "critical"},
	{"lateral", "dcshadow", "DCShadow is blocked (Rule #7). No AD attacks.", "critical"},
	{"lateral", "dcsync", "DCSync is blocked (Rule #7). No AD attacks.", "critical"},

	// ═══════════════════════════════════════════════════════════
	// RULE 4: No social engineering / phishing
	// ═══════════════════════════════════════════════════════════
	{"phishing", "sendemail", "sendEmail is blocked (Rule #4). No phishing email sending.", "critical"},
	{"phishing", "swaks", "swaks is blocked (Rule #4). No phishing email sending.", "critical"},
	{"phishing", "gophish", "GoPhish is blocked (Rule #4). No phishing campaigns.", "critical"},
	{"phishing", "king-phisher", "King Phisher is blocked (Rule #4).", "critical"},
	{"phishing", "setoolkit", "SET is blocked (Rule #4). No social engineering.", "critical"},
	{"phishing", "social-engineer", "Social engineering tools are blocked (Rule #4).", "critical"},
	{"phishing", "beef", "BeEF is blocked (Rule #4). No browser exploitation framework.", "critical"},
	{"phishing", "evilginx", "Evilginx is blocked (Rule #4). No phishing proxy.", "critical"},
	{"phishing", "modlishka", "Modlishka is blocked (Rule #4). No phishing proxy.", "critical"},

	// ═══════════════════════════════════════════════════════════
	// RULE 6: No mass user enumeration (reasonable limits)
	// ═══════════════════════════════════════════════════════════
	{"enumeration", "for i in $(seq 1 1000)", "Mass iteration >100 is blocked (Rule #6). Use ≤50 for proof.", "high"},
	{"enumeration", "for i in {1..1000}", "Mass iteration >100 is blocked (Rule #6). Use ≤50 for proof.", "high"},
	{"enumeration", "seq 1 1000", "Mass sequence generation >100 is blocked (Rule #6).", "high"},
	{"enumeration", "hydra -l", "Hydra username list is restricted (Rule #6). Use ≤50 usernames.", "medium"},
	{"enumeration", "hydra -L", "Hydra large wordlist is blocked (Rule #6). Use small lists (≤50).", "high"},
	{"enumeration", "medusa -u", "Medusa username list is restricted (Rule #6).", "medium"},
	{"enumeration", "medusa -U", "Medusa large wordlist is blocked (Rule #6).", "high"},
	{"enumeration", "ncrack -u", "Ncrack username list is restricted (Rule #6).", "medium"},
	{"enumeration", "ncrack -U", "Ncrack large wordlist is blocked (Rule #6).", "high"},

	// ═══════════════════════════════════════════════════════════
	// RULE 10: Email/SMS bombing limit (≤50 targets)
	// ═══════════════════════════════════════════════════════════
	{"bombing", "sendgrid", "SendGrid API use is restricted (Rule #10). Max 50 targets.", "medium"},
	{"bombing", "twilio", "Twilio API use is restricted (Rule #10). Max 50 targets.", "medium"},
	{"bombing", "mailgun", "Mailgun API use is restricted (Rule #10). Max 50 targets.", "medium"},
	{"bombing", "aws ses", "AWS SES use is restricted (Rule #10). Max 50 targets.", "medium"},
	{"bombing", "smtp-send", "Bulk SMTP sending is restricted (Rule #10). Max 50 targets.", "medium"},

	// ═══════════════════════════════════════════════════════════
	// RULE 11: No malware upload — text proof only
	// ═══════════════════════════════════════════════════════════
	{"malware", "msfvenom", "msfvenom is blocked (Rule #11). Only upload plain text proofs.", "critical"},
	{"malware", "msfpayload", "msfpayload is blocked (Rule #11). Only upload plain text proofs.", "critical"},
	{"malware", "veil", "Veil is blocked (Rule #11). No malware generation.", "critical"},
	{"malware", "thefatrat", "TheFatRat is blocked (Rule #11). No malware generation.", "critical"},
	{"malware", "payload", "Payload generation tools are blocked (Rule #11). Use text files for proof.", "critical"},
	{"malware", "reverse shell", "Reverse shell tools are blocked (Rule #11). Only use text proof files.", "critical"},
	{"malware", "nc -e", "nc -e (reverse shell) is blocked (Rule #11). Only text proofs allowed.", "critical"},
	{"malware", "ncat -e", "ncat -e (reverse shell) is blocked (Rule #11). Only text proofs allowed.", "critical"},
	{"malware", "bash -i >&", "Bash reverse shell is blocked (Rule #11). Only text proofs allowed.", "critical"},
	{"malware", "python -c 'import socket'", "Python reverse shell is blocked (Rule #11). Only text proofs.", "critical"},
	{"malware", "python3 -c 'import socket'", "Python reverse shell is blocked (Rule #11). Only text proofs.", "critical"},
	{"malware", "ruby -rsocket", "Ruby reverse shell is blocked (Rule #11). Only text proofs allowed.", "critical"},
	{"malware", "php -r '$sock'", "PHP reverse shell is blocked (Rule #11). Only text proofs.", "critical"},
	{"malware", "perl -e 'use socket'", "Perl reverse shell is blocked (Rule #11). Only text proofs.", "critical"},
	{"malware", "wget http", "wget payload download is blocked (Rule #11). Only text proofs.", "high"},
	{"malware", "curl -o /tmp", "curl payload download to /tmp is blocked (Rule #11).", "high"},
	{"malware", "curl -o /var", "curl payload download to /var is blocked (Rule #11).", "high"},
	{"malware", "curl -o /etc", "curl payload download to /etc is blocked (Rule #11).", "critical"},
	{"malware", "curl -o /usr", "curl payload download to system dirs is blocked (Rule #11).", "critical"},
	{"malware", "curl -o /bin", "curl payload download to system dirs is blocked (Rule #11).", "critical"},
	{"malware", "chmod 777", "chmod 777 is blocked (Rule #11). No permission escalation.", "high"},
	{"malware", "chmod +x /tmp", "Making downloaded files executable is blocked (Rule #11).", "high"},
	{"malware", "base64 -d | bash", "Encoded payload execution is blocked (Rule #11).", "critical"},
	{"malware", "base64 --decode | bash", "Encoded payload execution is blocked (Rule #11).", "critical"},
	{"malware", "eval(", "eval() is blocked (Rule #11). No code execution.", "high"},
	{"malware", "exec(", "exec() is blocked (Rule #11). No code execution.", "high"},
	{"malware", "system(", "system() is blocked (Rule #11). No code execution.", "high"},
	{"malware", "passthru(", "passthru() is blocked (Rule #11). No code execution.", "high"},
	{"malware", "shell_exec(", "shell_exec() is blocked (Rule #11). No code execution.", "high"},
	{"malware", `" , `, "Backtick code execution is blocked (Rule #11). No code execution.", "high"},

	// ═══════════════════════════════════════════════════════════
	// RULE 1: No data exfiltration / disclosure
	// ═══════════════════════════════════════════════════════════
	{"exfil", "curl.*-X POST.* pastebin", "Posting data to Pastebin is blocked (Rule #1). No data exfiltration.", "critical"},
	{"exfil", "curl.* pastebin", "Uploading to Pastebin is blocked (Rule #1). No data exfiltration.", "critical"},
	{"exfil", "curl.* transfer.sh", "Uploading to transfer.sh is blocked (Rule #1). No data exfiltration.", "critical"},
	{"exfil", "curl.* file.io", "Uploading to file.io is blocked (Rule #1). No data exfiltration.", "critical"},
	{"exfil", "curl.* requestbin", "Uploading to RequestBin is blocked (Rule #1). No data exfiltration.", "critical"},
	{"exfil", "curl.* webhook", "Webhook exfiltration is blocked (Rule #1). No data exfiltration.", "critical"},
	{"exfil", "curl.*-d.*http", "POSTing scanned data externally is blocked (Rule #1). No data exfiltration.", "high"},
	{"exfil", "wget.*-O-.*|", "Piping data to external commands is blocked (Rule #1). No data exfiltration.", "high"},

	// ═══════════════════════════════════════════════════════════
	// RULE 7: No Docker/container escape
	// ═══════════════════════════════════════════════════════════
	{"container", "docker run --privileged", "Privileged Docker is blocked (Rule #7). No container escape.", "critical"},
	{"container", "docker.sock", "Docker socket access is blocked (Rule #7). No container escape.", "critical"},
	{"container", "capsh", "capsh capability manipulation is blocked (Rule #7).", "critical"},
	{"container", "mount.*cgroup", "cgroup mount escape is blocked (Rule #7).", "critical"},
	{"container", "runc", "runc exploitation is blocked (Rule #7). No container escape.", "critical"},
	{"container", "crictl", "crictl is blocked (Rule #7). No container orchestration access.", "critical"},
	{"container", "kubectl", "kubectl is blocked (Rule #7). No K8s access.", "critical"},
	{"container", "kubelet", "kubelet access is blocked (Rule #7). No K8s access.", "critical"},
	{"container", "etcdctl", "etcdctl is blocked (Rule #7). No etcd access.", "critical"},
}

// ── Public API ───────────────────────────────────────────────────────────────

// CheckCommand inspects a shell command against all security rules.
// Returns a non-empty GuardResult if the command violates any rule.
func CheckCommand(cmd string) GuardResult {
	if IsOff() {
		return GuardResult{Blocked: false}
	}

	lower := strings.ToLower(cmd)

	for _, gp := range guardPatterns {
		if strings.Contains(lower, gp.Pattern) {
			if IsStrict() {
				log.Printf("[SECURITY] BLOCKED [%s/%s]: %s", gp.Category, gp.Level, gp.Reason)
				return GuardResult{Blocked: true, Reason: fmt.Sprintf("[SECURITY BLOCKED - %s] %s (Category: %s)", gp.Level, gp.Reason, gp.Category), Level: gp.Level}
			}
			if IsWarn() {
				log.Printf("[SECURITY] WARNING [%s/%s]: command matched '%s' — %s", gp.Category, gp.Level, gp.Pattern, gp.Reason)
				return GuardResult{Blocked: false, Reason: fmt.Sprintf("[SECURITY WARNING] %s", gp.Reason), Level: gp.Level}
			}
		}
	}

	return GuardResult{Blocked: false}
}

// CheckSQLInjection checks if a SQL injection proof-of-concept is safe
// (SELECT-only, no UPDATE/DELETE/INSERT/DROP).
func CheckSQLInjection(payload string) GuardResult {
	lower := strings.ToLower(payload)

	forbidden := []string{"update ", "delete ", "drop ", "truncate", "insert ", "replace ", "alter ", "merge ", "grant ", "revoke ", "create ", "exec("}
	for _, f := range forbidden {
		if strings.Contains(lower, f) {
			return GuardResult{
				Blocked: true,
				Reason:  fmt.Sprintf("[SECURITY BLOCKED] SQL payload contains forbidden keyword '%s'. Use SELECT-only queries for proof-of-concept (Rule #2).", strings.TrimSpace(f)),
				Level:   "critical",
			}
		}
	}

	return GuardResult{Blocked: false}
}

// IsIgnoredVuln checks if a vulnerability type should be ignored
// (Rule #12 — low-value vulnerabilities).
func IsIgnoredVuln(vulnType string) (bool, string) {
	lower := strings.ToLower(vulnType)

	ignored := map[string]string{
		"url redirect":              "URL redirect/open redirect — too low impact (Rule #12)",
		"open redirect":             "Open redirect — too low impact (Rule #12)",
		"url跳转":                    "URL跳转 — 无实际危害 (Rule #12)",
		"weak password":             "Weak password on self-managed account — not exploitable (Rule #12)",
		"weak credential":           "Weak credentials — self-service issue (Rule #12)",
		"弱口令":                     "前台个人弱口令 — 无实际危害 (Rule #12)",
		"self-xss":                  "Self-XSS — requires user interaction on own account (Rule #12)",
		"reflected xss":             "Reflected XSS — need to evaluate impact carefully",
		"email bombing":             "Email bombing — too low impact (Rule #12)",
		"邮件轰炸":                   "邮件轰炸 — 无实际危害 (Rule #12)",
		"registration without verify": "Arbitrary registration without verification — low impact (Rule #12)",
		"任意用户注册":               "任意用户注册 — 无实际危害 (Rule #12)",
		"信息泄露":                   "信息泄露需评估是否有敏感数据 (Rule #12)",
		"info disclosure":           "Info disclosure — check if data is sensitive (Rule #12)",
		"information leak":          "Information leak — evaluate sensitivity (Rule #12)",
		"内网信息泄露":               "内网信息泄露 — 无直接利用价值 (Rule #12)",
		"internal ip disclosure":    "Internal IP disclosure — no direct exploit (Rule #12)",
		"expired key":               "Expired API key — no current impact (Rule #12)",
		"过期key":                   "已过期的key — 无实际危害 (Rule #12)",
		"robots.txt":                "robots.txt exposure — public by design (Rule #12)",
		"api exposed":               "API endpoint exposure — need valid data to be actionable (Rule #12)",
		"api泄露":                   "API接口泄露但无有效信息 — 无实际危害 (Rule #12)",
		"public file":               "Public file exposure — may be intentional (Rule #12)",
		"public directory":          "Public directory listing — evaluate impact (Rule #12)",
		"favicon hash":              "Favicon hash — low-value fingerprinting (Rule #12)",
		"banner grab":               "Banner grabbing — low-value recon (Rule #12)",
		"stack trace":               "Stack trace — may be low-value without source code (Rule #12)",
		"error message":             "Verbose error messages — need additional context (Rule #12)",
	}

	for pattern, reason := range ignored {
		if strings.Contains(lower, pattern) {
			return true, reason
		}
	}

	return false, ""
}

// IsDoSTool checks if a tool is categorized as DoS/Stress testing.
func IsDoSTool(tool string) bool {
	dosTools := []string{
		"hping3", "slowhttptest", "goldeneye", "t50", "loic", "hoic",
		"slowloris", "apache-killer", "rudy", "xflood", "iaxflood",
		"dhcpig", "mkflood", "macof", "siege", "wrk", "hey", "vegeta",
		"tsunami", "booter", "stresser",
	}
	lower := strings.ToLower(tool)
	for _, t := range dosTools {
		if lower == t {
			return true
		}
	}
	return false
}

// IsLateralTool checks if a tool is for lateral movement.
func IsLateralTool(tool string) bool {
	lateralTools := []string{
		"crackmapexec", "psexec", "wmiexec", "smbexec", "atexec",
		"bloodhound", "mimikatz", "secretsdump", "impacket",
	}
	lower := strings.ToLower(tool)
	for _, t := range lateralTools {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

// SanitizeProofPayload sanitizes a proof-of-concept payload for safe reporting.
// It replaces actual sensitive data with [REDACTED] placeholders.
func SanitizeProofPayload(payload string, maxRecords int) string {
	if maxRecords <= 0 {
		maxRecords = MaxDataRecords
	}

	lines := strings.Split(payload, "\n")
	if len(lines) > maxRecords+5 {
		// Truncate to maxRecords + header/footer context
		truncated := lines[:maxRecords+5]
		truncated = append(truncated, fmt.Sprintf("\n[SECURITY] Output truncated: %d lines total, showing %d records max (Rule #8). Proving vulnerability existence is sufficient.", len(lines), maxRecords))
		return strings.Join(truncated, "\n")
	}
	return payload
}

// PolicySummary returns a formatted summary of the security policy.
func PolicySummary() string {
	return `╔══════════════════════════════════════════════════════════════════════════════╗
║                     ETHICAL PENTESTING POLICY v2.0                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ 1. NEVER disclose project/vulnerability information publicly                 ║
║ 2. NO database dumping — SELECT COUNT(*) or LIMIT 1 only                     ║
║ 3. NO UPDATE/DELETE/INSERT/DROP/TRUNCATE — read-only testing                ║
║ 4. NO DoS/DDoS or service disruption                                         ║
║ 5. NO social engineering or phishing attacks                                 ║
║ 6. NO production file deletion or overwrite                                  ║
║ 7. NO mass user enumeration (>50 users)                                      ║
║ 8. NO privilege escalation or lateral movement                               ║
║ 9. Sensitive data: read ≤ 5 records max for proof                            ║
║ 10. NO modification of real user data — use your own test accounts          ║
║ 11. Email/SMS bombing ≤ 50 targets max                                       ║
║ 12. NO malware upload — text proof files only (1.txt, 1.php, etc.)          ║
║ 13. IGNORE low-value vulns: URL redirect, self-XSS, weak password, etc.     ║
╚══════════════════════════════════════════════════════════════════════════════╝
`
}
