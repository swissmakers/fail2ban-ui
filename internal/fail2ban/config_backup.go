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

package fail2ban

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Stores an immutable recovery copy on the actual target.
type ConfigurationBackupper interface {
	BackupConfiguration(context.Context, string) error
	RestoreConfiguration(context.Context, string) error
	DeleteConfigurationBackup(context.Context, string) error
}

var backupIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,100}$`)

const maxConfigBackupBytes = 16 << 20

type configBackupFile struct {
	Data []byte      `json:"data"`
	Mode fs.FileMode `json:"mode"`
	UID  int         `json:"uid"`
	GID  int         `json:"gid"`
}
type configBackup struct {
	Files map[string]configBackupFile `json:"files"`
}

func backupFilePath(root, id string) (string, error) {
	if !backupIDPattern.MatchString(id) {
		return "", errors.New("invalid configuration backup id")
	}
	dir := filepath.Join(root, ".fail2ban-ui-operations", "backups")
	for _, p := range []string{filepath.Dir(dir), dir} {
		info, err := os.Lstat(p)
		if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return "", fmt.Errorf("unsafe backup directory %s", p)
		}
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	return filepath.Join(dir, id+".json"), nil
}
func isBackedUpConfig(name string) bool {
	if name == "jail.conf" || name == "jail.local" {
		return true
	}
	dir, file := filepath.Split(name)
	return (dir == "jail.d/" || dir == "filter.d/" || dir == "action.d/") && file != "" && (strings.HasSuffix(file, ".conf") || strings.HasSuffix(file, ".local"))
}
func configBackupFiles(root string) (map[string]configBackupFile, error) {
	result := map[string]configBackupFile{}
	total := 0
	add := func(name string) error {
		p := filepath.Join(root, name)
		info, err := os.Lstat(p)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("configuration backup requires regular files: %s", name)
		}
		total += int(info.Size())
		if total > maxConfigBackupBytes {
			return errors.New("configuration backup exceeds 16 MiB")
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		file := configBackupFile{Data: data, Mode: info.Mode().Perm(), UID: os.Getuid(), GID: os.Getgid()}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			file.UID, file.GID = int(stat.Uid), int(stat.Gid)
		}
		result[name] = file
		return nil
	}
	for _, name := range []string{"jail.conf", "jail.local"} {
		if err := add(name); err != nil {
			return nil, err
		}
	}
	for _, dir := range []string{"jail.d", "filter.d", "action.d"} {
		info, err := os.Lstat(filepath.Join(root, dir))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("unsafe configuration directory: %s", dir)
		}
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			name := dir + "/" + e.Name()
			if isBackedUpConfig(name) {
				if err := add(name); err != nil {
					return nil, err
				}
			}
		}
	}
	return result, nil
}
func (lc *LocalConnector) BackupConfiguration(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root := lc.configPath()
	path, err := backupFilePath(root, id)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("unsafe configuration backup")
		}
		_, err := readConfigurationBackup(path)
		return err
	} else if !os.IsNotExist(err) {
		return err
	}
	files, err := configBackupFiles(root)
	if err != nil {
		return err
	}
	data, err := json.Marshal(configBackup{Files: files})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return replaceFileAtomic(path, data, 0600)
}

func readConfigurationBackup(path string) (configBackup, error) {
	var backup configBackup
	info, err := os.Lstat(path)
	if err != nil {
		return backup, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxConfigBackupBytes*2 {
		return backup, errors.New("invalid configuration backup")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return backup, err
	}
	if err := json.Unmarshal(data, &backup); err != nil {
		return backup, err
	}
	if backup.Files == nil {
		return backup, errors.New("invalid configuration backup")
	}
	total := 0
	for name, f := range backup.Files {
		if !isBackedUpConfig(name) || f.Mode&^0777 != 0 || f.UID < 0 || f.GID < 0 {
			return backup, errors.New("unsafe entry in configuration backup")
		}
		total += len(f.Data)
		if total > maxConfigBackupBytes {
			return backup, errors.New("configuration backup exceeds 16 MiB")
		}
	}
	return backup, nil
}

func (lc *LocalConnector) RestoreConfiguration(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root := lc.configPath()
	path, err := backupFilePath(root, id)
	if err != nil {
		return err
	}
	backup, err := readConfigurationBackup(path)
	if err != nil {
		return err
	}
	current, err := configBackupFiles(root)
	if err != nil {
		return err
	}
	for name, f := range backup.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0755); err != nil {
			return err
		}
		path := filepath.Join(root, name)
		if existing, ok := current[name]; ok && bytes.Equal(existing.Data, f.Data) && existing.Mode == f.Mode && existing.UID == f.UID && existing.GID == f.GID {
			continue
		}
		if err := replaceFileAtomic(path, f.Data, f.Mode.Perm()); err != nil {
			return err
		}
		if err := os.Chown(path, f.UID, f.GID); err != nil && !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		err = file.Sync()
		file.Close()
		if err != nil {
			return err
		}
	}
	for name := range current {
		if _, ok := backup.Files[name]; !ok {
			if err := os.Remove(filepath.Join(root, name)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	for _, dir := range []string{root, filepath.Join(root, "jail.d"), filepath.Join(root, "filter.d"), filepath.Join(root, "action.d")} {
		if err := syncDir(dir); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
func (lc *LocalConnector) DeleteConfigurationBackup(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := backupFilePath(lc.configPath(), id)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// Python ships with Fail2ban -> a single remote process takes&restores the copy so
// SSH disconnects do not leave a partially transferred backup treated as valid
const remoteConfigBackupScript = `import os,sys,json,base64,stat,tempfile
root,ident,mode=sys.argv[1:]
if not ident or len(ident)>100 or any(not(c.isascii() and (c.isalnum() or c in '_-')) for c in ident): raise ValueError('invalid backup id')
store=os.path.join(root,'.fail2ban-ui-operations','backups')
for d in (os.path.dirname(store),store):
 if os.path.lexists(d) and (os.path.islink(d) or not os.path.isdir(d)): raise ValueError('unsafe backup directory')
path=os.path.join(store,ident+'.json')
def valid(name):
 return name in ('jail.conf','jail.local') or (name.count('/')==1 and name.split('/')[0] in ('jail.d','filter.d','action.d') and name.endswith(('.conf','.local')))
def collect():
 names=['jail.conf','jail.local']; result={}; total=0
 for d in ('jail.d','filter.d','action.d'):
  p=os.path.join(root,d)
  if os.path.lexists(p):
   if os.path.islink(p) or not os.path.isdir(p): raise ValueError('unsafe config directory')
   names.extend(d+'/'+n for n in os.listdir(p) if valid(d+'/'+n))
 for n in names:
  p=os.path.join(root,n)
  if not os.path.lexists(p): continue
  st=os.lstat(p)
  if not stat.S_ISREG(st.st_mode): raise ValueError('backup requires regular files: '+n)
  total+=st.st_size
  if total>16*1024*1024: raise ValueError('configuration backup exceeds 16 MiB')
  with open(p,'rb') as f: data=f.read()
  result[n]={'data':base64.b64encode(data).decode(),'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid}
 return result
def syncdir(p):
 fd=os.open(p,os.O_RDONLY)
 try: os.fsync(fd)
 finally: os.close(fd)
def atomic(p,data,perm,uid=None,gid=None):
 fd,tmp=tempfile.mkstemp(prefix='.f2bui-restore-',dir=os.path.dirname(p))
 try:
  with os.fdopen(fd,'wb') as f:
   f.write(data); f.flush()
   if uid is not None:
    try: os.fchown(f.fileno(),uid,gid)
    except PermissionError: pass # Restore usable configuration even without permission to restore its former owner.
   os.fchmod(f.fileno(),perm); os.fsync(f.fileno())
  os.replace(tmp,p); syncdir(os.path.dirname(p))
 finally:
  if os.path.exists(tmp): os.unlink(tmp)
def readbackup():
 st=os.lstat(path)
 if not stat.S_ISREG(st.st_mode) or st.st_size>32*1024*1024: raise ValueError('invalid backup')
 with open(path) as f: saved=json.load(f)['files']
 if not isinstance(saved,dict) or any(not valid(n) for n in saved): raise ValueError('unsafe backup path')
 total=0
 for n,item in saved.items():
  if not isinstance(item,dict) or type(item.get('mode')) is not int or item['mode'] & ~0o777 or any(type(item.get(k)) is not int or item[k]<0 for k in ('uid','gid')): raise ValueError('unsafe backup entry')
  item['decoded']=base64.b64decode(item['data'],validate=True); total+=len(item['decoded'])
  if total>16*1024*1024: raise ValueError('configuration backup exceeds 16 MiB')
 return saved
if mode=='backup':
 if os.path.lexists(path):
  if not stat.S_ISREG(os.lstat(path).st_mode): raise ValueError('unsafe backup file')
  readbackup()
 else:
  data=json.dumps({'files':collect()}).encode(); os.makedirs(store,mode=0o700,exist_ok=True); atomic(path,data,0o600)
elif mode=='restore':
 saved=readbackup()
 current=collect()
 for n,item in saved.items():
  old=current.get(n)
  if old and old['data']==item['data'] and all(old[k]==item[k] for k in ('mode','uid','gid')): continue
  p=os.path.join(root,n); os.makedirs(os.path.dirname(p),exist_ok=True); atomic(p,item['decoded'],item['mode'],item['uid'],item['gid'])
 for n in current:
  if n not in saved: os.unlink(os.path.join(root,n))
 for d in (root,)+tuple(os.path.join(root,d) for d in ('jail.d','filter.d','action.d')):
  if os.path.isdir(d): syncdir(d)
elif mode=='delete':
 if os.path.lexists(path): os.unlink(path); syncdir(store)
else: raise ValueError('invalid backup mode')
`

func (sc *SSHConnector) configurationBackup(ctx context.Context, id, mode string) error {
	if !backupIDPattern.MatchString(id) {
		return errors.New("invalid configuration backup id")
	}
	_, err := sc.runRemoteCommand(ctx, []string{shellJoin("python3", "-c", remoteConfigBackupScript, sc.getFail2banPath(ctx), id, mode)})
	return err
}
func (sc *SSHConnector) BackupConfiguration(ctx context.Context, id string) error {
	return sc.configurationBackup(ctx, id, "backup")
}
func (sc *SSHConnector) RestoreConfiguration(ctx context.Context, id string) error {
	return sc.configurationBackup(ctx, id, "restore")
}
func (sc *SSHConnector) DeleteConfigurationBackup(ctx context.Context, id string) error {
	return sc.configurationBackup(ctx, id, "delete")
}
