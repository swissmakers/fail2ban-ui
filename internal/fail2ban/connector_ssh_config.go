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

// Remote Fail2ban configuration management: jails, filters, logpath and
// filter testing, and the managed jail.local structure.
package fail2ban

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
)

func (sc *SSHConnector) GetFilterConfig(ctx context.Context, filterName string) (string, string, error) {
	filterName = strings.TrimSpace(filterName)
	if err := ValidateFilterName(filterName); err != nil {
		return "", "", err
	}

	fail2banPath := sc.getFail2banPath(ctx)
	content, path, err := sc.readRemoteWithLocalFallback(ctx, FilterDir(fail2banPath), filterName)
	if err != nil {
		return "", "", fmt.Errorf("failed to read remote filter config (tried .local and .conf): %w", err)
	}
	return content, path, nil
}

// Writes dir/name.local, seeding it from the shipped .conf first so the override keeps whatever the distribution provided
func (sc *SSHConnector) writeConfigOverride(ctx context.Context, dir, name, content, kind string) error {
	if _, err := sc.runRemoteCommand(ctx, []string{"mkdir", "-p", dir}); err != nil {
		return fmt.Errorf("failed to create %s directory: %w", filepath.Base(dir), err)
	}
	if err := sc.ensureRemoteLocalFile(ctx, dir, name); err != nil {
		return fmt.Errorf("failed to ensure .local file for %s %s: %w", kind, name, err)
	}
	if err := sc.writeRemoteFile(ctx, filepath.Join(dir, name+".local"), content); err != nil {
		return fmt.Errorf("failed to write %s config: %w", kind, err)
	}
	return nil
}

func (sc *SSHConnector) SetFilterConfig(ctx context.Context, filterName, content string) error {
	filterName = strings.TrimSpace(filterName)
	if err := ValidateFilterName(filterName); err != nil {
		return err
	}
	return sc.writeConfigOverride(ctx, FilterDir(sc.getFail2banPath(ctx)), filterName, content, "filter")
}

// =========================================================================
//  Jail Operations
// =========================================================================

// Accumulates jails parsed from jail.d file contents, letting .local definitions override .conf ones (and same-type re-definitions win).
type jailAccumulator struct {
	jails  []JailInfo
	index  map[string]int
	source map[string]string
}

func newJailAccumulator() *jailAccumulator {
	return &jailAccumulator{index: make(map[string]int), source: make(map[string]string)}
}

func (a *jailAccumulator) add(content, fileType string) {
	for _, jail := range parseJailConfigContent(content) {
		if jail.JailName == "" || jail.JailName == "DEFAULT" {
			continue
		}
		idx, seen := a.index[jail.JailName]
		switch {
		case !seen:
			a.index[jail.JailName] = len(a.jails)
			a.source[jail.JailName] = fileType
			a.jails = append(a.jails, jail)
		case fileType == "local" || a.source[jail.JailName] == fileType:
			a.jails[idx].Enabled = jail.Enabled
			a.source[jail.JailName] = fileType
		}
	}
}

func buildJailDirDumpScript(jailDPath string) (string, error) {
	quotedDir, err := quoteRemotePath(jailDPath)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`for f in %[1]s/*.local; do
	if [ -f "$f" ]; then
		echo "%[2]s$f"
		cat "$f"
		echo "%[3]s"
	fi
done
for f in %[1]s/*.conf; do
	if [ -f "$f" ] && [ ! -f "${f%%.conf}.local" ]; then
		echo "%[2]s$f"
		cat "$f"
		echo "%[3]s"
	fi
done
`, quotedDir, batchFileBegin, batchFileEnd), nil
}

// Classifies a dumped jail.d file by extension for the .local-wins
func jailFileType(path string) string {
	if strings.HasSuffix(path, ".local") {
		return "local"
	}
	return "conf"
}

func (sc *SSHConnector) GetAllJails(ctx context.Context) ([]JailInfo, error) {
	jailDPath := JailDir(sc.getFail2banPath(ctx))
	script, err := buildJailDirDumpScript(jailDPath)
	if err != nil {
		return nil, err
	}
	output, err := sc.runRemoteCommand(ctx, []string{script})
	if err != nil {
		return nil, fmt.Errorf("failed to read jail definitions from %s on %s: %w", jailDPath, sc.server.Name, err)
	}

	acc := newJailAccumulator()
	for _, file := range parseRemoteFileDump(output) {
		acc.add(file.content, jailFileType(file.path))
	}
	return acc.jails, nil
}

func (sc *SSHConnector) UpdateJailEnabledStates(ctx context.Context, updates map[string]bool) error {
	fail2banPath := sc.getFail2banPath(ctx)
	jailDPath := JailDir(fail2banPath)

	for jailName, enabled := range updates {
		jailName = strings.TrimSpace(jailName)
		if jailName == "" {
			debugf("Skipping empty jail name in updates map")
			continue
		}
		if err := ValidateJailName(jailName); err != nil {
			return fmt.Errorf("invalid jail name in updates map: %w", err)
		}

		localPath := filepath.Join(jailDPath, jailName+".local")
		confPath := filepath.Join(jailDPath, jailName+".conf")
		findScript := fmt.Sprintf(`
			files=$(grep -lxF '[%s]' %s/*.local 2>/dev/null || true)
			if [ -z "$files" ]; then
				if [ -f "%s" ]; then
					cp "%s" "%s"
				else
					echo "[%s]" > "%s"
				fi
				files="%s"
			fi
			for f in $files; do
				echo "%s$f"
				cat "$f"
				echo "%s"
			done
		`, jailName, jailDPath, confPath, confPath, localPath, jailName, localPath, localPath,
			batchFileBegin, batchFileEnd)

		dump, err := sc.runRemoteCommand(ctx, []string{findScript})
		if err != nil {
			return fmt.Errorf("failed to locate .local files for jail %s: %w", jailName, err)
		}

		for _, rf := range parseRemoteFileDump(dump) {
			jailFilePath := rf.path
			if !strings.HasPrefix(jailFilePath, jailDPath+"/") || !strings.HasSuffix(jailFilePath, ".local") {
				debugf("Skipping unexpected jail file path from remote: %s", jailFilePath)
				continue
			}
			content := rf.content
			if !containsJailSection(content, jailName) {
				return fmt.Errorf("refusing to rewrite %s: section [%s] not found in remote file content", jailFilePath, jailName)
			}
			newContent := rewriteJailEnabled(content, jailName, enabled)
			if err := sc.writeRemoteFile(ctx, jailFilePath, newContent); err != nil {
				return fmt.Errorf("failed to write jail .local file %s: %w", jailFilePath, err)
			}
			debugf("Updated jail %s: enabled = %t (file: %s)", jailName, enabled, jailFilePath)
		}
	}
	return nil
}

func (sc *SSHConnector) GetFilters(ctx context.Context) ([]string, error) {
	filterDPath := FilterDir(sc.getFail2banPath(ctx))

	localFiles, err := sc.listRemoteFiles(ctx, filterDPath, ".local")
	if err != nil {
		debugf("Failed to list .local filters on server %s: %v", sc.server.Name, err)
	}
	confFiles, err := sc.listRemoteFiles(ctx, filterDPath, ".conf")
	if err != nil {
		debugf("Failed to list .conf filters on server %s: %v", sc.server.Name, err)
	}
	return dedupeConfigBaseNames(localFiles, confFiles), nil
}

// =========================================================================
//  Filter Include Resolution
// =========================================================================

func (sc *SSHConnector) remoteFilterIncludeReader(ctx context.Context, filterDPath string) filterIncludeReader {
	return func(baseName string) (string, string, error) {
		if _, err := resolveWithinDir(filterDPath, baseName, ".local"); err != nil {
			return "", "", fmt.Errorf("invalid include filter name %q: %w", baseName, err)
		}
		content, path, err := sc.readRemoteWithLocalFallback(ctx, filterDPath, baseName)
		if err != nil {
			return "", "", fmt.Errorf("could not load included filter file: %w", err)
		}
		return content, path, nil
	}
}

func (sc *SSHConnector) resolveFilterIncludesRemote(ctx context.Context, filterContent string, filterDPath string, currentFilterName string) (string, error) {
	return resolveFilterIncludesWith(filterContent, currentFilterName, sc.remoteFilterIncludeReader(ctx, filterDPath))
}

func (sc *SSHConnector) TestFilter(ctx context.Context, filterName string, logLines []string, filterContent string) (string, string, error) {
	cleaned := normalizeLogLines(logLines)
	if len(cleaned) == 0 {
		return "No log lines provided.\n", "", nil
	}
	filterName = strings.TrimSpace(filterName)
	if err := ValidateFilterName(filterName); err != nil {
		return "", "", err
	}
	fail2banPath := sc.getFail2banPath(ctx)
	localPath := filepath.Join(FilterDir(fail2banPath), filterName+".local")
	confPath := filepath.Join(FilterDir(fail2banPath), filterName+".conf")

	const heredocMarker = "F2B_FILTER_TEST_LOG"
	logContent := strings.Join(cleaned, "\n")
	var prologue string
	if filterContent != "" {
		resolvedContent, err := sc.resolveFilterIncludesRemote(ctx, filterContent, FilterDir(fail2banPath), filterName)
		if err != nil {
			debugf("Warning: failed to resolve filter includes remotely, using original content: %v", err)
			resolvedContent = filterContent
		}
		if !strings.HasSuffix(resolvedContent, "\n") {
			resolvedContent += "\n"
		}
		prologue = fmt.Sprintf(`TMPFILTER=$(mktemp /tmp/fail2ban-filter-XXXXXX.conf)
trap 'rm -f "$TMPFILTER"' EXIT
echo '%s' | base64 -d > "$TMPFILTER"
FILTER_PATH="$TMPFILTER"`, base64.StdEncoding.EncodeToString([]byte(resolvedContent)))
	} else {
		prologue = fmt.Sprintf(`LOCAL_PATH=%[1]q
CONF_PATH=%[2]q
if [ -f "$LOCAL_PATH" ]; then
  FILTER_PATH="$LOCAL_PATH"
elif [ -f "$CONF_PATH" ]; then
  FILTER_PATH="$CONF_PATH"
else
  echo "Filter not found: checked both $LOCAL_PATH and $CONF_PATH" >&2
  exit 1
fi`, localPath, confPath)
	}

	script := fmt.Sprintf(`set -e
%[1]s
echo "%[2]s$FILTER_PATH"
TMPFILE=$(mktemp /tmp/fail2ban-test-XXXXXX.log)
trap 'rm -f "$TMPFILE" ${TMPFILTER:+"$TMPFILTER"}' EXIT
cat <<'%[3]s' > "$TMPFILE"
%[4]s
%[3]s
fail2ban-regex "$TMPFILE" "$FILTER_PATH" || true
`, prologue, filterPathMarker, heredocMarker, logContent)

	out, err := sc.runRemoteCommand(ctx, []string{script})
	if err != nil {
		return "", "", err
	}

	output, filterPath := splitFilterTestOutput(out)
	if filterPath == "" {
		filterPath = confPath
	}
	return output, filterPath, nil
}

// Splits the marker line carrying the resolved filter path from the fail2ban-regex output
func splitFilterTestOutput(out string) (output, filterPath string) {
	var outputLines []string
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, filterPathMarker); ok {
			filterPath = strings.TrimSpace(rest)
			continue
		}
		outputLines = append(outputLines, line)
	}
	return strings.Join(outputLines, "\n"), filterPath
}

func (sc *SSHConnector) GetJailConfig(ctx context.Context, jail string) (string, string, error) {
	jail = strings.TrimSpace(jail)
	if err := ValidateJailName(jail); err != nil {
		return "", "", err
	}

	fail2banPath := sc.getFail2banPath(ctx)
	jailDPath := JailDir(fail2banPath)
	content, path, err := sc.readRemoteWithLocalFallback(ctx, jailDPath, jail)
	if err != nil {
		return fmt.Sprintf("[%s]\n", jail), filepath.Join(jailDPath, jail+".local"), nil
	}
	return content, path, nil
}

func (sc *SSHConnector) SetJailConfig(ctx context.Context, jail, content string) error {
	jail = strings.TrimSpace(jail)
	if err := ValidateJailName(jail); err != nil {
		return err
	}
	return sc.writeConfigOverride(ctx, JailDir(sc.getFail2banPath(ctx)), jail, content, "jail")
}

const (
	logpathMarkerNoAccess = "F2BUI_NOACCESS"
	logpathMarkerNoDir    = "F2BUI_NODIR"
)

func parseLogpathProbe(out string) ([]string, error) {
	var matches []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch line {
		case logpathMarkerNoAccess:
			return nil, ErrLogpathInaccessible
		case logpathMarkerNoDir:
			return []string{}, nil
		default:
			matches = append(matches, line)
		}
	}
	return matches, nil
}

func (sc *SSHConnector) TestLogpath(ctx context.Context, logpath string) ([]string, error) {
	if logpath == "" {
		return []string{}, nil
	}

	logpath = strings.TrimSpace(logpath)
	hasWildcard := strings.ContainsAny(logpath, "*?[")

	var script string
	if hasWildcard {
		script = fmt.Sprintf(`
LOGPATH=%q
DIR=$(dirname "$LOGPATH")
if [ ! -d "$DIR" ]; then echo %s; exit 0; fi
if [ ! -r "$DIR" ] || [ ! -x "$DIR" ]; then echo %s; exit 0; fi
find "$DIR" -maxdepth 1 -path "$LOGPATH" -type f 2>/dev/null | sort
`, logpath, logpathMarkerNoDir, logpathMarkerNoAccess)
	} else {
		script = fmt.Sprintf(`
LOGPATH=%q
if [ -f "$LOGPATH" ]; then echo "$LOGPATH"; exit 0; fi
if [ -d "$LOGPATH" ]; then
  if [ ! -r "$LOGPATH" ] || [ ! -x "$LOGPATH" ]; then echo %s; exit 0; fi
  find "$LOGPATH" -maxdepth 1 -type f 2>/dev/null | sort
  exit 0
fi
DIR=$(dirname "$LOGPATH")
if [ -d "$DIR" ] && { [ ! -r "$DIR" ] || [ ! -x "$DIR" ]; }; then echo %s; exit 0; fi
echo %s
`, logpath, logpathMarkerNoAccess, logpathMarkerNoAccess, logpathMarkerNoDir)
	}

	out, err := sc.runRemoteCommand(ctx, []string{script})
	if err != nil {
		return nil, fmt.Errorf("failed to probe logpath on %s: %w", sc.server.Name, err)
	}

	return parseLogpathProbe(out)
}

func (sc *SSHConnector) TestLogpathWithResolution(ctx context.Context, logpath string) (originalPath, resolvedPath string, files []string, err error) {
	originalPath = strings.TrimSpace(logpath)
	if originalPath == "" {
		return originalPath, "", []string{}, nil
	}

	if len(extractVariablesFromString(originalPath)) == 0 {
		files, err = sc.TestLogpath(ctx, originalPath)
		if err != nil {
			return originalPath, originalPath, nil, fmt.Errorf("failed to test logpath: %w", err)
		}
		return originalPath, originalPath, files, nil
	}

	configFiles, dumpErr := sc.dumpConfigTree(ctx)
	if dumpErr != nil {
		return originalPath, "", nil, fmt.Errorf("failed to read remote fail2ban configuration: %w", dumpErr)
	}
	resolvedPath, err = resolveLogpathVariablesFrom(originalPath, snapshotVariableSource{files: configFiles})
	if err != nil {
		return originalPath, "", nil, fmt.Errorf("failed to resolve variables: %w", err)
	}

	files, err = sc.TestLogpath(ctx, resolvedPath)
	if err != nil {
		return originalPath, resolvedPath, nil, fmt.Errorf("failed to test logpath: %w", err)
	}

	return originalPath, resolvedPath, files, nil
}

func (sc *SSHConnector) UpdateDefaultSettings(ctx context.Context) error {
	return sc.EnsureJailLocalStructure(ctx)
}

func (sc *SSHConnector) CheckJailLocalIntegrity(ctx context.Context) (bool, bool, error) {
	jailLocalPath := JailLocal(sc.getFail2banPath(ctx))
	output, err := sc.runRemoteCommand(ctx, []string{"cat", jailLocalPath})
	if err != nil {
		if strings.Contains(err.Error(), "No such file") || strings.Contains(output, "No such file") {
			return false, false, nil
		}
		return false, false, fmt.Errorf("failed to read jail.local on %s: %w", sc.server.Name, err)
	}
	hasUIAction := strings.Contains(output, managedJailLocalMarker)
	return true, hasUIAction, nil
}

func (sc *SSHConnector) EnsureJailLocalStructure(ctx context.Context) error {
	jailLocalPath := JailLocal(sc.getFail2banPath(ctx))

	exists, hasUI, chkErr := sc.CheckJailLocalIntegrity(ctx)
	if chkErr != nil {
		debugf("Warning: could not check jail.local integrity on %s: %v", sc.server.Name, chkErr)
	}
	if exists && !hasUI {
		debugf("jail.local on server %s exists but is not managed by Fail2ban-UI - skipping overwrite", sc.server.Name)
		return nil
	}

	content := mustProvider().BuildJailLocalContent()
	return sc.writeRemoteFile(ctx, jailLocalPath, content)
}

func (sc *SSHConnector) createConfigFile(ctx context.Context, dir, name, content, kind string) error {
	if _, err := sc.runRemoteCommand(ctx, []string{"mkdir", "-p", dir}); err != nil {
		return fmt.Errorf("failed to create %s directory: %w", filepath.Base(dir), err)
	}
	localPath := filepath.Join(dir, name+".local")
	if err := sc.writeRemoteFile(ctx, localPath, content); err != nil {
		return fmt.Errorf("failed to create %s file: %w", kind, err)
	}
	return nil
}

// Removes both dir/name.local and dir/name.conf
func (sc *SSHConnector) deleteConfigFiles(ctx context.Context, dir, name, kind string) error {
	localPath := filepath.Join(dir, name+".local")
	confPath := filepath.Join(dir, name+".conf")
	if _, err := sc.runRemoteCommand(ctx, []string{"rm", "-f", localPath, confPath}); err != nil {
		return fmt.Errorf("failed to delete %s files %s or %s: %w", kind, localPath, confPath, err)
	}
	return nil
}

func (sc *SSHConnector) CreateJail(ctx context.Context, jailName, content string) error {
	if err := ValidateJailName(jailName); err != nil {
		return err
	}
	// A jail file is only meaningful with its section header
	expectedSection := fmt.Sprintf("[%s]", jailName)
	if !strings.HasPrefix(strings.TrimSpace(content), expectedSection) {
		content = expectedSection + "\n" + content
	}
	return sc.createConfigFile(ctx, JailDir(sc.getFail2banPath(ctx)), jailName, content, "jail")
}

func (sc *SSHConnector) DeleteJail(ctx context.Context, jailName string) error {
	if err := ValidateJailName(jailName); err != nil {
		return err
	}
	return sc.deleteConfigFiles(ctx, JailDir(sc.getFail2banPath(ctx)), jailName, "jail")
}

func (sc *SSHConnector) CreateFilter(ctx context.Context, filterName, content string) error {
	if err := ValidateFilterName(filterName); err != nil {
		return err
	}
	return sc.createConfigFile(ctx, FilterDir(sc.getFail2banPath(ctx)), filterName, content, "filter")
}

func (sc *SSHConnector) DeleteFilter(ctx context.Context, filterName string) error {
	if err := ValidateFilterName(filterName); err != nil {
		return err
	}
	return sc.deleteConfigFiles(ctx, FilterDir(sc.getFail2banPath(ctx)), filterName, "filter")
}
