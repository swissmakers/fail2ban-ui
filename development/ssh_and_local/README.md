# SSH, local, and agent development stack

This stack provides a complete test environment covering all three connector types:

- **two local Fail2Ban instances** (containers) for testing one or two local connectors side by side,
- a **remote Fail2Ban instance over SSH** (container) for the SSH connector,
- **Fail2Ban plus fail2ban-ui-agent** (container) for the HTTP agent connector.

**Warning:** This setup is for development only. See [Production considerations](#production-considerations).

## Services

### Fail2ban-Local


| Property  | Value                                           |
| --------- | ----------------------------------------------- |
| Container | `DEV_fail2ban-local`                            |
| Purpose   | Local Fail2Ban instance for the local connector |
| Network   | `host` mode, for iptables access                |
| Config    | `./fail2ban-config-local/`                      |
| Socket    | `./f2b-run-local/`                              |


### Fail2ban-Local-Secondary


| Property                        | Value                                                                    |
| ------------------------------- | ------------------------------------------------------------------------ |
| Container                       | `DEV_fail2ban-local-secondary`                                           |
| Purpose                         | Second local Fail2Ban instance, for testing two independent local connectors at once |
| Network                         | bridge mode, unlike the primary, which uses host mode                    |
| Config                          | `./fail2ban-config-local-secondary/`                                     |
| Socket                          | `./f2b-run-local-secondary/`                                             |
| Paths inside `DEV_fail2ban-ui`  | `/etc/fail2ban-secondary` (config) and `/var/run/fail2ban-secondary` (socket) |


Configure it in the UI as a second server of type **Local**, pointing at the `-secondary` config and socket paths above. The primary instance uses the default `/etc/fail2ban` and `/var/run/fail2ban`.


### Fail2ban-SSH


| Property  | Value                                       |
| --------- | ------------------------------------------- |
| Container | `DEV_fail2ban-ssh`                          |
| Purpose   | Remote Fail2Ban instance reachable over SSH |
| Network   | bridge mode                                 |
| SSH port  | `2222` (mapped from container port 22)      |
| SSH user  | `testuser`                                  |
| SSH key   | auto-generated in `./ssh-keys/`             |
| Config    | `./fail2ban-config-ssh/`                    |


### Fail2ban-Agent


| Property  | Value                                                                                                                                                                                                                                                            |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Container | `DEV_fail2ban-agent`                                                                                                                                                                                                                                             |
| Purpose   | Fail2Ban plus **fail2ban-ui-agent** (HTTP API) on port **9700**, no SSH; tests the agent connector                                                                                                                                                               |
| Image     | Prebuilt `[swissmakers/fail2ban-ui-agent](https://hub.docker.com/r/swissmakers/fail2ban-ui-agent)`, the LinuxServer Fail2Ban base with the agent baked in. Sources: [github.com/swissmakers/fail2ban-ui-agent](https://github.com/swissmakers/fail2ban-ui-agent) |
| Network   | bridge; publishes `9700:9700`                                                                                                                                                                                                                                    |
| Config    | `./fail2ban-config-agent/` (created on first start)                                                                                                                                                                                                              |


### Fail2ban-UI


| Property  | Value                                                                                                        |
| --------- | ------------------------------------------------------------------------------------------------------------ |
| Container | `DEV_fail2ban-ui`                                                                                            |
| Port      | `3080`, bound to `0.0.0.0`                                                                                   |
| Base path | `/dev` (`BASE_PATH=/dev`), so the UI lives at `http://localhost:3080/dev/`; visiting `/` redirects there      |
| Callback  | `CALLBACK_URL=http://10.88.0.1:3080/dev` - the Podman default bridge gateway; change it if your bridge differs |
| Purpose   | The application under test, managing all local, SSH and agent instances                                      |


## Setup

### 1. Build the Fail2Ban UI image

```bash
cd /opt/fail2ban-ui
podman build -t localhost/fail2ban-ui:dev .
# or
docker build -t localhost/fail2ban-ui:dev .
```

### 1b. fail2ban-ui-agent image (optional)

Compose pulls `swissmakers/fail2ban-ui-agent:latest` by default. To refresh manually:

```bash
podman pull swissmakers/fail2ban-ui-agent:latest
# or
docker pull swissmakers/fail2ban-ui-agent:latest
```

To develop the agent itself: clone [fail2ban-ui-agent](https://github.com/swissmakers/fail2ban-ui-agent), build the image or a static binary per that repository's README, then either run that image or use the optional bind-mount and custom-init lines in `container-compose.yml` (commented out) to replace the binary inside the dev container.

### 2. Start the services

```bash
cd /opt/fail2ban-ui/development/ssh_and_local
podman compose up -d
# or
docker-compose up -d
```

### 3. Wait for the SSH container setup

On first start, the SSH container needs a moment to generate SSH keys (if not present), configure the SSH server, set up user permissions, and configure sudoers. Verify in the logs:

```bash
podman logs DEV_fail2ban-ssh
```

### 4. Configure Fail2Ban UI

1. **Open the UI** at `http://localhost:3080/dev/`. The stack sets `BASE_PATH=/dev`, so visiting `http://localhost:3080/` redirects there. With `BIND_ADDRESS=0.0.0.0` and host networking, the UI is also reachable on the host's other addresses.
2. **Add the local server.** Under **Manage Servers**, the local Fail2Ban instance should be auto-detected; enable the local connector.
3. **Add the SSH server.** Under **Manage Servers**, click **Add Server** and configure:

  | Field    | Value                                |
  | -------- | ------------------------------------ |
  | Name     | `SSH Test Server`                    |
  | Type     | `SSH`                                |
  | Host     | `127.0.0.1`                          |
  | Port     | `2222`                               |
  | SSH User | `testuser`                           |
  | SSH Key  | `/config/.ssh/id_rsa` (auto-mounted) |

   Enable the connector and click **Test Connection**.

## SSH connection details


| Property                | Value                 |
| ----------------------- | --------------------- |
| Host                    | `127.0.0.1`           |
| Port                    | `2222`                |
| User                    | `testuser`            |
| Key path (in container) | `/config/.ssh/id_rsa` |
| Key path (host)         | `./ssh-keys/id_rsa`   |


Manual connection test:

```bash
podman exec -it DEV_fail2ban-ui ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o BatchMode=yes \
  -i /config/.ssh/id_rsa \
  -p 2222 \
  testuser@127.0.0.1
```

## Configuration

### Fail2Ban UI environment variables

Edit `container-compose.yml` to customize:

```yaml
environment:
  - PORT=3080
  - BIND_ADDRESS=0.0.0.0
  - BASE_PATH=/dev                            # remove to serve the UI at the root
  - CALLBACK_URL=http://10.88.0.1:3080/dev    # must include BASE_PATH
  - CALLBACK_SECRET=same-as-ui-callback-secret
  - AUTODARK=true
  # - OIDC_ENABLED=true                       # use development/oidc/ for a full OIDC stack
```

If you remove `BASE_PATH`, drop the `/dev` suffix from `CALLBACK_URL` as well. See [docs/configuration.md](../../docs/configuration.md#http-base-path-subpath-deployment).

### SSH container

The SSH container is pre-configured with:

- passwordless SSH key authentication,
- sudo permissions for `fail2ban-client *` and `systemctl restart fail2ban`,
- the file permissions (FACLs) needed on the Fail2Ban configuration directories,
- root access for network management.

To modify the SSH configuration, edit the `command` section in `container-compose.yml`.

## Volume structure

```
./config/                  # Fail2Ban UI configuration and database
./ssh-keys/                # SSH key pair (shared between containers)
./fail2ban-config-local/             # Local Fail2Ban configuration (primary)
./f2b-run-local/                     # Local Fail2Ban socket directory (primary)
./fail2ban-config-local-secondary/   # Local Fail2Ban configuration (secondary)
./f2b-run-local-secondary/           # Local Fail2Ban socket directory (secondary)
./fail2ban-config-ssh/               # SSH Fail2Ban configuration
./fail2ban-config-agent/             # Agent Fail2Ban configuration
```

## Test scenarios

### 1. Local connector

1. Enable the local connector in Fail2Ban UI.
2. Create a test jail.
3. Verify the jail appears on the dashboard.
4. Test ban and unban operations.
5. Verify that configuration changes persist.

### 2. Agent connector

1. Start the agent container: `podman compose up -d fail2ban-agent`. The stack uses the prebuilt agent image; see [step 1b](#1b-fail2ban-ui-agent-image-optional) for a newer tag or a local build.
2. Check the logs: `podman logs DEV_fail2ban-agent`. Fail2Ban should start and the agent should listen on `9700`.
3. Quick check from the host:
  ```bash
   curl -sS -H 'X-F2B-Token: dev-agent-secret-change-me' http://127.0.0.1:9700/healthz
  ```
4. In Fail2Ban UI under **Manage Servers**, add a server with type **Agent**, agent URL `http://127.0.0.1:9700` (or the container IP from the bridge), and agent secret `dev-agent-secret-change-me` - it must match `AGENT_SECRET` in `container-compose.yml`.
5. Optional: uncomment the `AGENT_CALLBACK_`* environment variables on `fail2ban-agent` to exercise the ban/unban callbacks toward Fail2Ban UI.

### 3. SSH connector

1. Add the SSH server in Fail2Ban UI.
2. Test the connection; it should succeed.
3. Create a test jail on the remote server.
4. Verify the jail appears on the dashboard.
5. Test ban and unban operations.
6. Verify that configuration changes sync to the remote host.

### 4. Multi-server management

1. Enable both the local and the SSH connector.
2. Verify both servers appear in the server selector.
3. Switch between servers.
4. Verify each server's jails are isolated.
5. Test operations on each server independently.
6. Add the secondary local instance as a third server (type **Local**, config `/etc/fail2ban-secondary`, socket `/var/run/fail2ban-secondary`) and verify that jail lists, bans, and configuration edits stay isolated between the two local connectors.

## Troubleshooting

### SSH connection fails

1. Check that the SSH container is ready:
  ```bash
   podman logs DEV_fail2ban-ssh | tail -20
  ```
2. Verify the SSH keys exist:
  ```bash
   ls -la ./ssh-keys/
  ```
3. Test SSH manually:
  ```bash
   podman exec -it DEV_fail2ban-ui ssh -v -i /config/.ssh/id_rsa -p 2222 testuser@127.0.0.1
  ```
4. Check the SSH container port:
  ```bash
   netstat -tlnp | grep 2222
  ```

### Local connector issues

1. Check that the socket exists:
  ```bash
   ls -la ./f2b-run-local/
  ```
2. Verify the permissions:
  ```bash
   podman exec -it DEV_fail2ban-local ls -la /var/run/fail2ban/
  ```
3. Check the Fail2Ban status:
  ```bash
   podman exec -it DEV_fail2ban-local fail2ban-client status
  ```

### Permission errors

- Ensure the volumes have correct SELinux labels (`:z` or `:Z`).
- Check that the container runs with the required capabilities.
- Verify the file permissions in the mounted directories.

## Cleanup

Remove all containers and volumes:

```bash
podman compose down -v
# or
docker-compose down -v
```

**Warning:** This deletes all development data - configurations, SSH keys, and databases. SSH keys are regenerated on the next start.

## Production considerations

This setup is for development only. For production:

- Use proper SSH key management, not the auto-generated key from this stack.
- Use dedicated service accounts, not `testuser`.
- Use HTTPS/TLS, not HTTP, and a properly configured reverse proxy.
- Use strong, randomly generated secrets, including the session secrets.
- Enable proper logging and monitoring.

