package vuln

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	Description string `json:"description"`
}

type Rule struct {
	ID          string
	Severity    string
	Pattern     *regexp.Regexp
	Description string
}

var DefaultRules = []Rule{
	{
		ID:          "SKW-001",
		Severity:    "CRITICAL",
		Pattern:     regexp.MustCompile(`(?i)(curl|wget|nc|bash|sh)\s+https?:\/\/`),
		Description: "Remote arbitrary script download or execution in prompt/contract",
	},
	{
		ID:          "SKW-002",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|password|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]`),
		Description: "Potential hardcoded plaintext credential found",
	},
	{
		ID:          "SKW-003",
		Severity:    "CRITICAL",
		Pattern:     regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior)\s+instructions`),
		Description: "Direct prompt-injection bypass instruction detected",
	},
}

func ScanDirectory(dirPath string) ([]Finding, error) {
	var findings []Finding

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}

		// Only scan text files
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".md" && ext != ".yaml" && ext != ".yml" && ext != ".json" && ext != ".txt" && ext != ".sh" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		lineNum := 0
		rel, _ := filepath.Rel(dirPath, path)

		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			for _, rule := range DefaultRules {
				if rule.Pattern.MatchString(line) {
					findings = append(findings, Finding{
						RuleID:      rule.ID,
						Severity:    rule.Severity,
						FilePath:    rel,
						LineNumber:  lineNum,
						Description: rule.Description,
					})
				}
			}
		}

		return scanner.Err()
	})

	return findings, err
}
