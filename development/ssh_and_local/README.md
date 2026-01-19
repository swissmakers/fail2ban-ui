# SSH and Local Fail2ban Development Setup

This setup provides a complete testing environment for Fail2ban UI with:
- **Local Fail2ban instance** (container) - for testing local connector
- **Remote Fail2ban instance via SSH** (container) - for testing SSH connector

## Services

### 1. Fail2ban-Local
- **Container:** `DEV_fail2ban-local`
- **Purpose:** Local Fail2ban instance for testing local connector
- **Network:** `host` mode (for iptables access)
- **Config:** `./fail2ban-config-local/`
- **Socket:** `./f2b-run-local/`

### 2. Fail2ban-SSH
- **Container:** `DEV_fail2ban-ssh`
- **Purpose:** Remote Fail2ban instance accessible via SSH
- **Network:** Bridge mode
- **SSH Port:** `2222` (mapped from container port 22)
- **SSH User:** `testuser`
- **SSH Key:** Auto-generated in `./ssh-keys/`
- **Config:** `./fail2ban-config-ssh/`

### 3. Fail2ban-UI
- **Container:** `DEV_fail2ban-ui`
- **Port:** `3080`
- **URL:** `http://172.16.10.18:3080` (or configured BIND_ADDRESS)
- **Purpose:** Main application for managing both Fail2ban instances

## Setup Instructions

### 1. Build the Fail2ban-UI Image

```bash
cd /opt/fail2ban-ui
podman build -t localhost/fail2ban-ui:dev .
# or
docker build -t localhost/fail2ban-ui:dev .
```

### 2. Start the Services

```bash
cd /opt/fail2ban-ui/development/ssh_and_local
podman compose up -d
# or
docker-compose up -d
```

### 3. Wait for SSH Container Setup

The SSH container takes a moment to:
- Generate SSH keys (if not present)
- Configure SSH server
- Set up user permissions
- Configure sudoers

Check logs to verify:
```bash
podman logs DEV_fail2ban-ssh
```

Look for:
```
========================================
SSH Test Container Ready
========================================
```

### 4. Configure Fail2ban-UI

1. **Access Fail2ban UI:**
   - Open `http://172.16.10.18:3080` (or your configured BIND_ADDRESS:PORT)
   - Or if using host network: `http://localhost:3080`

2. **Add Local Server:**
   - Go to "Manage Servers"
   - The local Fail2ban instance should be auto-detected
   - Enable the local connector

3. **Add SSH Server:**
   - Go to "Manage Servers"
   - Click "Add Server"
   - Configure:
     - **Name:** `SSH Test Server`
     - **Type:** `SSH`
     - **Host:** `127.0.0.1`
     - **Port:** `2222`
     - **SSH User:** `testuser`
     - **SSH Key:** Select `/config/.ssh/id_rsa` (auto-mounted)
   - Enable the connector
   - Click "Test Connection" to verify

## SSH Connection Details

- **Host:** `127.0.0.1`
- **Port:** `2222`
- **User:** `testuser`
- **Key Path (in container):** `/config/.ssh/id_rsa`
- **Key Path (host):** `./ssh-keys/id_rsa`

### Test SSH Connection Manually

```bash
# From host
podman exec -it DEV_fail2ban-ui ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o BatchMode=yes \
  -i /config/.ssh/id_rsa \
  -p 2222 \
  testuser@127.0.0.1
```

## Configuration

### Fail2ban-UI Environment Variables

Edit `container-compose.yml` to customize:

```yaml
environment:
  - PORT=3080
  - BIND_ADDRESS=172.16.10.18  # Change to your IP or 0.0.0.0
  # OIDC settings (if testing OIDC)
  - OIDC_ENABLED=false  # Set to true to enable OIDC
```

### SSH Container Customization

The SSH container is pre-configured with:
- Passwordless SSH key authentication
- Sudo permissions for fail2ban-client commands
- Proper file permissions (FACLs) for Fail2ban config directories
- Root access for network management

To modify SSH configuration, edit the `command` section in `container-compose.yml`.

## Volume Structure

```
./config/              # Fail2ban-UI configuration and database
./ssh-keys/            # SSH key pair (shared between containers)
./fail2ban-config-local/  # Local Fail2ban configuration
./f2b-run-local/       # Local Fail2ban socket directory
./fail2ban-config-ssh/ # SSH Fail2ban configuration
```

## Testing Scenarios

### 1. Local Connector Test

1. Enable local connector in Fail2ban-UI
2. Create a test jail
3. Verify jail appears in dashboard
4. Test ban/unban operations
5. Verify configuration changes persist

### 2. SSH Connector Test

1. Add SSH server in Fail2ban-UI
2. Test connection (should succeed)
3. Create a test jail on remote server
4. Verify jail appears in dashboard
5. Test ban/unban operations
6. Verify configuration changes sync to remote

### 3. Multi-Server Management

1. Enable both local and SSH connectors
2. Verify both servers appear in server selector
3. Switch between servers
4. Verify each server's jails are isolated
5. Test operations on each server independently

## Troubleshooting

### SSH Connection Fails

1. **Check SSH container is ready:**
   ```bash
   podman logs DEV_fail2ban-ssh | tail -20
   ```

2. **Verify SSH keys exist:**
   ```bash
   ls -la ./ssh-keys/
   ```

3. **Test SSH manually:**
   ```bash
   podman exec -it DEV_fail2ban-ui ssh -v -i /config/.ssh/id_rsa -p 2222 testuser@127.0.0.1
   ```

4. **Check SSH container port:**
   ```bash
   netstat -tlnp | grep 2222
   ```

### Local Connector Issues

1. **Check socket exists:**
   ```bash
   ls -la ./f2b-run-local/
   ```

2. **Verify permissions:**
   ```bash
   podman exec -it DEV_fail2ban-local ls -la /var/run/fail2ban/
   ```

3. **Check Fail2ban status:**
   ```bash
   podman exec -it DEV_fail2ban-local fail2ban-client status
   ```

### Permission Errors

- Ensure volumes have correct SELinux labels (`:z` or `:Z`)
- Check container is running with required capabilities
- Verify file permissions in mounted directories

## Cleanup

To remove all containers and volumes:

```bash
podman compose down -v
# or
docker-compose down -v
```

This will remove:
- All containers
- Volume data (configs, SSH keys, databases)

**Note:** This deletes all development data. SSH keys will be regenerated on next start.

## Production Considerations

⚠️ **This setup is for development only!**

For production:
- Use proper SSH key management (not this auto-generated key)
- Use dedicated service accounts (not testuser)
- Use HTTPS/TLS (not HTTP) / Configure proper reverse proxy
- Use strong, randomly generated secrets
- Use secure session secrets
- Enable proper logging and monitoring
