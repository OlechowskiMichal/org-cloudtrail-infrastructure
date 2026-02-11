package test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoHardcodedCredentialsInTerraform scans .tf files for hardcoded AWS credentials.
func TestNoHardcodedCredentialsInTerraform(t *testing.T) {
	t.Parallel()

	tofuDir := "../tofu"

	var tfFiles []string
	err := filepath.WalkDir(tofuDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".tf" {
			tfFiles = append(tfFiles, path)
		}
		return nil
	})
	require.NoError(t, err)

	if len(tfFiles) == 0 {
		t.Skip("No .tf files found in tofu/ directory; skipping credential scan")
	}

	credentialPatterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"AWS Secret Key literal", regexp.MustCompile(`(?i)secret_key\s*=\s*"[^"]{20,}"`)},
		{"AWS Access Key literal", regexp.MustCompile(`(?i)access_key\s*=\s*"AKIA[^"]*"`)},
	}

	for _, tf := range tfFiles {
		content, err := os.ReadFile(filepath.Clean(tf))
		require.NoError(t, err)

		lines := strings.Split(string(content), "\n")
		inBlockComment := false
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "/*") {
				inBlockComment = true
			}
			if strings.Contains(trimmed, "*/") {
				inBlockComment = false
				continue
			}
			if inBlockComment {
				continue
			}
			if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
				continue
			}
			for _, cp := range credentialPatterns {
				if cp.re.MatchString(line) {
					t.Errorf("%s:%d: found %s: %s",
						filepath.Base(tf), i+1, cp.name, trimmed)
				}
			}
		}
	}
}

// TestNoHardcodedCredentialsInGo scans .go files for hardcoded AWS credentials.
func TestNoHardcodedCredentialsInGo(t *testing.T) {
	t.Parallel()

	var goFiles []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() && (d.Name() == "vendor" || d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if !d.IsDir() && filepath.Ext(path) == ".go" {
			goFiles = append(goFiles, path)
		}
		return nil
	})
	require.NoError(t, err)

	if len(goFiles) == 0 {
		t.Skip("No .go files found; skipping credential scan")
	}

	credentialPatterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"AWS Secret Key literal", regexp.MustCompile(`(?i)secret_key\s*=\s*"[^"]{20,}"`)},
		{"AWS Access Key literal", regexp.MustCompile(`(?i)access_key\s*=\s*"AKIA[^"]*"`)},
	}

	for _, goFile := range goFiles {
		content, err := os.ReadFile(filepath.Clean(goFile))
		require.NoError(t, err)

		lines := strings.Split(string(content), "\n")
		for _, cp := range credentialPatterns {
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") {
					continue
				}
				if cp.re.MatchString(line) {
					t.Errorf("%s:%d: found %s: %s",
						filepath.Base(goFile), i+1, cp.name, trimmed)
				}
			}
		}
	}
}

// TestNoSecretsInVariables checks that no variables hold secret values
// without the sensitive flag.
func TestNoSecretsInVariables(t *testing.T) {
	t.Parallel()

	variablesFile := "../tofu/variables.tf"
	content, err := os.ReadFile(filepath.Clean(variablesFile))
	if os.IsNotExist(err) {
		t.Skip("No variables.tf found; skipping secrets-in-variables scan")
	}
	require.NoError(t, err)

	blocks := strings.Split(string(content), "variable ")
	for _, block := range blocks[1:] {
		checkVariableBlockForSecrets(t, block)
	}

	checkDefaultValuesForSecrets(t, string(content))
}

func checkVariableBlockForSecrets(t *testing.T, block string) {
	t.Helper()

	sensitiveNames := []string{
		"password", "secret", "token",
		"api_key", "private_key", "credentials",
	}

	nameEnd := strings.Index(block, `"`)
	if nameEnd == -1 {
		return
	}
	remaining := block[nameEnd+1:]
	nameClose := strings.Index(remaining, `"`)
	if nameClose == -1 {
		return
	}
	varName := strings.ToLower(remaining[:nameClose])

	for _, sensitive := range sensitiveNames {
		if strings.Contains(varName, sensitive) {
			assert.Contains(t, block, "sensitive",
				"Variable %q contains '%s' in name but lacks sensitive = true",
				varName, sensitive)
		}
	}
}

func checkDefaultValuesForSecrets(t *testing.T, content string) {
	t.Helper()

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "default") || !strings.Contains(trimmed, "=") {
			continue
		}
		if strings.Contains(trimmed, "AKIA") || strings.Contains(trimmed, "aws_secret") {
			t.Errorf("variables.tf line %d: default value may contain a secret: %s", i+1, trimmed)
		}
	}
}
