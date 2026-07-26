// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2026 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU Affero General Public License, Version 3 (AGPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Remote file operations over SSH: reading, writing, listing, and the
// framed multi-file dump format shared by the batched fetches.
package fail2ban

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	bannedSectionEnd      = "F2BUI_BANNED_END"
	batchJailLocalBegin   = "F2BUI_JAILLOCAL_BEGIN"
	batchJailLocalMissing = "F2BUI_JAILLOCAL_MISSING"
	batchEnd              = "F2BUI_BATCH_END"
	batchFileBegin        = "F2BUI_FILE_BEGIN:"
	batchFileEnd          = "F2BUI_FILE_END"
	filterPathMarker      = "FILTER_PATH:"
)

type remoteFile struct {
	path    string
	content string
}

func parseRemoteFileDump(out string) []remoteFile {
	var files []remoteFile
	var current *remoteFile
	var content strings.Builder
	flush := func() {
		if current == nil {
			return
		}
		current.content = strings.TrimSuffix(content.String(), "\n")
		files = append(files, *current)
		current = nil
		content.Reset()
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, batchFileBegin):
			flush()
			current = &remoteFile{path: strings.TrimPrefix(trimmed, batchFileBegin)}
		case trimmed == batchFileEnd:
			flush()
		case current != nil && strings.HasSuffix(line, batchFileEnd):
			content.WriteString(strings.TrimSuffix(line, batchFileEnd))
			content.WriteString("\n")
			flush()
		case current != nil:
			content.WriteString(line)
			content.WriteString("\n")
		}
	}
	flush()
	return files
}

// =========================================================================
//  Remote File Operations
// =========================================================================

// List files in a remote directory using find.
func (sc *SSHConnector) listRemoteFiles(ctx context.Context, directory, pattern string) ([]string, error) {
	cmd := fmt.Sprintf(`find "%s" -maxdepth 1 -type f -name "*%s" ! -name ".*" 2>/dev/null | sort`, directory, pattern)

	out, err := sc.runRemoteCommand(ctx, []string{cmd})
	if err != nil {
		return nil, fmt.Errorf("failed to list files in %s: %w", directory, err)
	}

	var files []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "." || strings.HasPrefix(line, "./") {
			continue
		}
		if strings.HasSuffix(line, pattern) {
			if strings.HasPrefix(line, directory) {
				files = append(files, line)
			} else if !strings.HasPrefix(line, "/") {
				fullPath := filepath.Join(directory, line)
				files = append(files, fullPath)
			}
		}
	}

	return files, nil
}

func quoteRemotePath(filePath string) (string, error) {
	if strings.ContainsAny(filePath, "'\n") {
		return "", fmt.Errorf("unsupported character in remote path %q", filePath)
	}
	return "'" + filePath + "'", nil
}

func (sc *SSHConnector) readRemoteFile(ctx context.Context, filePath string) (string, error) {
	quoted, err := quoteRemotePath(filePath)
	if err != nil {
		return "", err
	}
	content, err := sc.runRemoteCommand(ctx, []string{"cat " + quoted})
	if err != nil {
		return "", fmt.Errorf("failed to read remote file %s: %w", filePath, err)
	}
	return content, nil
}

func (sc *SSHConnector) readRemoteWithLocalFallback(ctx context.Context, dir, name string) (string, string, error) {
	localPath := filepath.Join(dir, name+".local")
	if content, err := sc.readRemoteFile(ctx, localPath); err == nil {
		return content, localPath, nil
	}
	confPath := filepath.Join(dir, name+".conf")
	content, err := sc.readRemoteFile(ctx, confPath)
	if err != nil {
		return "", "", fmt.Errorf("could not read '%s' or '%s': %w", localPath, confPath, err)
	}
	return content, confPath, nil
}

const remoteWriteDelimiter = "F2BUI_REMOTE_EOF"

func buildRemoteWriteScript(filePath, content string) (string, error) {
	quoted, err := quoteRemotePath(filePath)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == remoteWriteDelimiter {
			return "", fmt.Errorf("content contains the heredoc delimiter %q", remoteWriteDelimiter)
		}
	}
	body := strings.TrimSuffix(content, "\n")
	return fmt.Sprintf("cat > %s <<'%s'\n%s\n%s\n", quoted, remoteWriteDelimiter, body, remoteWriteDelimiter), nil
}

func (sc *SSHConnector) writeRemoteFile(ctx context.Context, filePath, content string) error {
	script, err := buildRemoteWriteScript(filePath, content)
	if err != nil {
		return fmt.Errorf("refusing to write remote file %s: %w", filePath, err)
	}
	if _, err := sc.runRemoteCommand(ctx, []string{script}); err != nil {
		return fmt.Errorf("failed to write remote file %s: %w", filePath, err)
	}
	return nil
}

func (sc *SSHConnector) ensureRemoteLocalFile(ctx context.Context, basePath, name string) error {
	localPath := fmt.Sprintf("%s/%s.local", basePath, name)
	confPath := fmt.Sprintf("%s/%s.conf", basePath, name)

	if err := ValidateFilterName(name); err != nil {
		return fmt.Errorf("invalid config name %q: %w", name, err)
	}

	script := fmt.Sprintf(`
		if [ ! -f "%s" ]; then
			if [ -f "%s" ]; then
				cp "%s" "%s"
			else
				# Create empty .local file if neither exists
				touch "%s"
			fi
		fi
	`, localPath, confPath, confPath, localPath, localPath)

	_, err := sc.runRemoteCommand(ctx, []string{script})
	if err != nil {
		return fmt.Errorf("failed to ensure remote .local file %s: %w", localPath, err)
	}
	return nil
}

func (sc *SSHConnector) getFail2banPath(ctx context.Context) string {
	sc.pathMutex.RLock()
	path := sc.fail2banPath
	sc.pathMutex.RUnlock()
	if path != "" {
		return path
	}

	checkCmd := `test -d "/config/fail2ban" && echo "/config/fail2ban" || echo "/etc/fail2ban"`
	out, err := sc.runRemoteCommand(ctx, []string{checkCmd})
	if err != nil {
		debugf("fail2ban path probe failed for %s, assuming %s (will retry): %v", sc.server.Name, DefaultConfigRoot, err)
		return DefaultConfigRoot
	}
	probed := strings.TrimSpace(out)
	if probed == "" {
		return DefaultConfigRoot
	}

	sc.pathMutex.Lock()
	defer sc.pathMutex.Unlock()
	if sc.fail2banPath == "" {
		sc.fail2banPath = probed
	}
	return sc.fail2banPath
}

func buildConfigTreeDumpScript(configRoot string) (string, error) {
	quotedRoot, err := quoteRemotePath(configRoot)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`find %[1]s -type f \( -name '*.conf' -o -name '*.local' \) | sort | while IFS= read -r f; do
	echo "%[2]s$f"
	cat "$f"
	echo "%[3]s"
done
`, quotedRoot, batchFileBegin, batchFileEnd), nil
}

func (sc *SSHConnector) dumpConfigTree(ctx context.Context) ([]remoteFile, error) {
	configRoot := sc.getFail2banPath(ctx)
	script, err := buildConfigTreeDumpScript(configRoot)
	if err != nil {
		return nil, err
	}
	out, err := sc.runRemoteCommand(ctx, []string{script})
	if err != nil {
		return nil, fmt.Errorf("failed to read config tree from %s on %s: %w", configRoot, sc.server.Name, err)
	}
	return parseRemoteFileDump(out), nil
}
