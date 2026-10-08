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
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

const (
	bannedSectionEnd      = "F2BUI_BANNED_END"
	batchJailLocalBegin   = "F2BUI_JAILLOCAL_BEGIN"
	batchJailLocalMissing = "F2BUI_JAILLOCAL_MISSING"
	batchActionBegin      = "F2BUI_ACTION_BEGIN"
	batchActionMissing    = "F2BUI_ACTION_MISSING"
	batchEnd              = "F2BUI_BATCH_END"
	batchFileBegin        = "F2BUI_FILE_BEGIN:"
	batchFileEnd          = "F2BUI_FILE_END"
	filterPathMarker      = "FILTER_PATH:"
	missingToolsMarker    = "F2BUI_MISSING_TOOLS:"
	permWarningMarker     = "F2BUI_PERM_WARNING:"
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

// Quotes one word for the remote POSIX shell.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// Builds a remote command line with every word quoted.
func shellJoin(words ...string) string {
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = shellQuote(w)
	}
	return strings.Join(quoted, " ")
}

// List files in a remote directory using find.
func (sc *SSHConnector) listRemoteFiles(ctx context.Context, directory, pattern string) ([]string, error) {
	cmd := fmt.Sprintf(`find %s -maxdepth 1 -type f -name %s ! -name '.*' 2>/dev/null | sort`, shellQuote(directory), shellQuote("*"+pattern))

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

func (sc *SSHConnector) readRemoteFile(ctx context.Context, filePath string) (string, error) {
	quoted := shellQuote(filePath)
	parent := shellQuote(filepath.Dir(filePath))
	grandparent := shellQuote(filepath.Dir(filepath.Dir(filePath)))
	script := fmt.Sprintf("if { [ ! -e %s ] && [ -x %s ]; } || { [ -d %s ] && [ -x %s ] && [ ! -e %s ] && [ ! -L %s ]; }; then printf 'F2BUI_NOT_FOUND'; else cat %s; fi",
		parent, grandparent, parent, parent, quoted, quoted, quoted)
	content, err := sc.runRemoteCommand(ctx, []string{script})
	if err != nil {
		return "", fmt.Errorf("failed to read remote file %s: %w", filePath, err)
	}
	if content == "F2BUI_NOT_FOUND" {
		return "", fmt.Errorf("%s: %w", filePath, fs.ErrNotExist)
	}
	return content, nil
}

func (sc *SSHConnector) readRemoteWithLocalFallback(ctx context.Context, dir, name string) (string, string, error) {
	localPath := filepath.Join(dir, name+".local")
	if content, err := sc.readRemoteFile(ctx, localPath); err == nil {
		return content, localPath, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", "", err
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
	return buildRemoteWriteScriptMode(filePath, content, false)
}

func buildRemoteWriteScriptMode(filePath, content string, private bool) (string, error) {
	quoted := shellQuote(filePath)
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == remoteWriteDelimiter {
			return "", fmt.Errorf("content contains the heredoc delimiter %q", remoteWriteDelimiter)
		}
	}
	body := strings.TrimSuffix(content, "\n")
	// stat -c works on GNU and BusyBox; chmod --reference is GNU-only and would abort under set -e.
	mode := "mode=644; if [ -f \"$target\" ]; then mode=$(stat -c %a \"$target\" 2>/dev/null) || mode=644; fi; chmod \"$mode\" \"$tmp\""
	if private {
		mode = "chmod 600 \"$tmp\""
	}
	return fmt.Sprintf(`set -e
target=%s
if [ -L "$target" ]; then target=$(readlink -f "$target"); fi
umask 077
tmp=$(mktemp "${target}.f2bui.XXXXXX")
backup=''
trap 'rm -f "$tmp"; if [ -n "$backup" ]; then rm -f "$backup"; fi' EXIT HUP INT TERM
cat > "$tmp" <<'%s'
%s
%s
%s
unchanged=false
if [ -f "$target" ]; then
  # Keep trailing newlines and stop on read errors; minimal hosts may lack cmp.
  current=$(cat "$target" && printf '.')
  staged=$(cat "$tmp" && printf '.')
  if [ "$current" = "$staged" ]; then unchanged=true; fi
fi
if [ "$unchanged" = true ]; then
  rm -f "$tmp"
else
  if [ -f "$target" ]; then
    backup=$(mktemp "${target}.backup.XXXXXX")
    cat "$target" > "$backup"
    chmod 600 "$backup"
    mv -f "$backup" "${target}.f2bui.bak"
    backup=''
  fi
  mv -f "$tmp" "$target"
  sync
fi
trap - EXIT HUP INT TERM
`, quoted, remoteWriteDelimiter, body, remoteWriteDelimiter, mode), nil
}

func buildEnsureActionScript(actionPath, content string) (string, error) {
	quotedDir := shellQuote(filepath.Dir(actionPath))
	quotedFile := shellQuote(actionPath)
	write, err := buildRemoteWriteScriptMode(actionPath, content, true)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`set -e
mkdir -p %s
umask 077
%schmod 600 %s 2>/dev/null || true
if [ -n "$(find %s -perm -o+r 2>/dev/null)" ]; then printf '%s%%s\n' %s; fi
missing=''
for t in jq curl; do
	command -v "$t" >/dev/null 2>&1 || missing="${missing:+$missing,}$t"
done
if [ -n "$missing" ]; then printf '%s%%s\n' "$missing"; fi
`, quotedDir, write, quotedFile, quotedFile, permWarningMarker, quotedFile, missingToolsMarker), nil
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
	// The probe prints one of two constants; take the last line so a login banner cannot poison the cache.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	probed := strings.TrimSpace(lines[len(lines)-1])
	if probed != "/config/fail2ban" && probed != DefaultConfigRoot {
		debugf("unexpected fail2ban path probe output for %s, assuming %s: %q", sc.server.Name, DefaultConfigRoot, out)
		return DefaultConfigRoot
	}

	sc.pathMutex.Lock()
	defer sc.pathMutex.Unlock()
	if sc.fail2banPath == "" {
		sc.fail2banPath = probed
	}
	return sc.fail2banPath
}

func buildConfigTreeDumpScript(configRoot string) string {
	return fmt.Sprintf(`find %[1]s -type f \( -name '*.conf' -o -name '*.local' \) | sort | while IFS= read -r f; do
	echo "%[2]s$f"
	cat "$f"
	echo "%[3]s"
done
`, shellQuote(configRoot), batchFileBegin, batchFileEnd)
}

func (sc *SSHConnector) dumpConfigTree(ctx context.Context) ([]remoteFile, error) {
	configRoot := sc.getFail2banPath(ctx)
	out, err := sc.runRemoteCommand(ctx, []string{buildConfigTreeDumpScript(configRoot)})
	if err != nil {
		return nil, fmt.Errorf("failed to read config tree from %s on %s: %w", configRoot, sc.server.Name, err)
	}
	return parseRemoteFileDump(out), nil
}
