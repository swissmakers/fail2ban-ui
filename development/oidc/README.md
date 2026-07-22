# OIDC development stack

This stack provides a complete OIDC test environment for Fail2Ban UI with Keycloak, Pocket-ID, and Authentik.

**Warning:** This setup is for development only. See [Production considerations](#production-considerations) before deploying anything similar in production.

## Services

### Keycloak (primary, default)


| Property            | Value                                    |
| ------------------- | ---------------------------------------- |
| Container           | `DEV_keycloak`                           |
| Port                | `3000` (mapped from internal `8080`)     |
| Management port     | `9000` (health checks)                   |
| URL / admin console | `http://localhost:3000`                  |
| Data                | `./keycloak-data/`, `./keycloak-db/`     |
| Database            | PostgreSQL (container `DEV_keycloak-db`) |


The recommended provider for testing; the OIDC client is configured automatically.

### Pocket-ID (alternative 1)


| Property  | Value                                      |
| --------- | ------------------------------------------ |
| Container | `DEV_pocket-id` (commented out by default) |
| Port      | `3005` (when enabled)                      |
| URL       | `http://localhost:3005`                    |
| Data      | `./pocket-id-data/`                        |


Lightweight OIDC provider with passkey support. Uncomment it in `container-compose.yml` to use it.

### Authentik (alternative 2)


| Property   | Value                                                                     |
| ---------- | ------------------------------------------------------------------------- |
| Containers | `DEV_authentik-server`, `DEV_authentik-worker` (commented out by default) |
| Ports      | `3007` (HTTP), `3008` (HTTPS) when enabled                                |
| URL        | `http://localhost:3007`                                                   |
| Data       | `./authentik-media/`, `./authentik-db/`                                   |


Full-featured identity provider with OIDC support. Requires migrations and initial setup; uncomment it in `container-compose.yml` to use it.

### Fail2Ban UI


| Property      | Value                                     |
| ------------- | ----------------------------------------- |
| Container     | `DEV_fail2ban-ui-oidc`                    |
| Port          | `3080`                                    |
| URL           | `http://localhost:3080`                   |
| OIDC provider | Keycloak (default, configurable)          |
| Network       | host mode, to reach Keycloak on localhost |


## Quick start

The OIDC client is configured automatically for Keycloak: start the containers and the flow works without manual provider setup. All services bind to `0.0.0.0`, so they are reachable from any network interface.

### Remote server access

The defaults use `localhost`, which only works for a browser on the same machine. For access from a remote browser, set the server's IP address or hostname.

**Option 1: `.env` file (recommended)**

1. Copy the example file:
  ```bash
   cd /opt/fail2ban-ui/development/oidc
   cp .env.example .env
  ```
2. Edit `.env` with your server's IP address or hostname:
  ```bash
   # Example for server IP 172.16.10.18:
   PUBLIC_FRONTEND_URL=http://172.16.10.18:3080
   KEYCLOAK_URL=http://172.16.10.18:3000
   KEYCLOAK_PUBLIC_URL=http://172.16.10.18:3000
  ```
3. Start the containers; Compose loads `.env` automatically:
  ```bash
   podman compose up -d
  ```

**Option 2: environment variables**

```bash
export PUBLIC_FRONTEND_URL=http://YOUR_SERVER_IP:3080
export KEYCLOAK_URL=http://YOUR_SERVER_IP:3000
export KEYCLOAK_PUBLIC_URL=http://YOUR_SERVER_IP:3000

cd /opt/fail2ban-ui/development/oidc
podman compose up -d
```

**Important:**

- Without these values, the redirect URIs use `localhost` and do not work from remote browsers.
- After changing the values, the Keycloak client may need to be recreated so the redirect URIs are updated:
  ```bash
  podman compose down
  rm -rf config/keycloak-client-secret
  podman compose up -d
  ```
  Alternatively, update the client manually in the Keycloak admin console: **Clients -> fail2ban-ui**, then adjust "Valid redirect URIs" and "Valid post logout redirect URIs" and save.

## Setup

### 1. Build the Fail2Ban UI image

```bash
cd /opt/fail2ban-ui
podman build -t localhost/fail2ban-ui:dev .
# or
docker build -t localhost/fail2ban-ui:dev .
```

### 2. Start the services

```bash
cd /opt/fail2ban-ui/development/oidc
podman compose up -d
# or
docker-compose up -d
```

**Note:**

- Keycloak needs 30-60 seconds to start fully.
- The fail2ban-ui container waits for Keycloak (`depends_on`).
- If fail2ban-ui is stuck in "Created" status, wait for Keycloak to report "healthy" (`podman compose ps`), or start it manually with `podman start DEV_fail2ban-ui-oidc` - it retries the connection.

### 3. Automatic Keycloak client configuration

The OIDC client is created automatically by the `keycloak-init` container. No manual provider configuration is required. The init container:

- waits for Keycloak to be ready,
- creates the `fail2ban-ui` OIDC client,
- configures redirect URIs and web origins,
- configures the post-logout redirect URI for the logout flow,
- saves the client secret to `/config/keycloak-client-secret`, from which fail2ban-ui reads it automatically.

**Note:** If you change `PUBLIC_FRONTEND_URL` after the client was created, delete the existing client and let `keycloak-init` recreate it, or update the client manually in the Keycloak admin console to include the new redirect URIs.

If you see a "Client not found" error, the `keycloak-init` container has not run or has failed:

1. Check that Keycloak is healthy:
  ```bash
   podman compose ps keycloak
  ```
2. Run the init container manually:
  ```bash
   cd /opt/fail2ban-ui/development/oidc
   podman compose run --rm keycloak-init
  ```
3. Verify the client secret was created:
  ```bash
   ls -la config/keycloak-client-secret
   cat config/keycloak-client-secret
  ```
4. Restart fail2ban-ui:
  ```bash
   podman compose restart fail2ban-ui
  ```

### Manual client configuration (fallback)

If the automatic configuration fails, create the client by hand:

1. **Wait for Keycloak.** Check `podman logs DEV_keycloak` for the "Keycloak started" message; `podman compose ps` should show "healthy".
2. **Open the admin console** at `http://localhost:3000` (or the host's IP) and log in with username `admin`, password `admin`.
3. **Select the realm.** The default configuration uses the `master` realm, which is already selected. A custom realm is optional; see below.
4. **Create the OIDC client:**
  - In the sidebar, open **Clients** and click **Create client**.
  - **Client ID:** `fail2ban-ui` - must match `OIDC_CLIENT_ID` in `container-compose.yml`.
  - **Client protocol:** `openid-connect`. Click **Next**.
  - **Client authentication:** toggle **ON** (confidential client). Leave **Authorization** off and the authentication flow at the defaults. Click **Next**.
  - **Login settings:** leave Root URL and Home URL empty. Set **Valid redirect URIs** to `http://localhost:3080/auth/callback` (must match exactly) and **Web origins** to `http://localhost:3080`. Click **Save**.
5. **Copy the client secret.** On the client page, open the **Credentials** tab and copy the secret. In `container-compose.yml`, replace `change-me-secret` in the line `- OIDC_CLIENT_SECRET=change-me-secret` with that value.
6. **Restart fail2ban-ui:**
  ```bash
   podman compose restart fail2ban-ui
  ```
7. **Create a test user** (recommended):
  - **Users -> Create new user**, set a username (for example `testuser`) and optionally an email. Click **Create**.
  - On the **Credentials** tab, set a password and toggle **Temporary** off, so no password reset is forced on first login. Save.

Then open `http://localhost:3080`: you are redirected to the Keycloak login, and after authentication back to Fail2Ban UI.

### Optional: custom realm

To use a custom realm instead of `master`:

1. In the Keycloak admin console, open the realm dropdown (top left) and click **Create Realm**.
2. Set the realm name (for example `myrealm`), enable it, and click **Create**.
3. In `container-compose.yml`, set:
  ```yaml
   - OIDC_ISSUER_URL=http://localhost:3000/realms/myrealm
  ```
4. Restart fail2ban-ui and create the OIDC client in the new realm as described above.

### 4. Test the authentication

1. Verify the application started:
  ```bash
   podman logs DEV_fail2ban-ui-oidc
   # Look for: "OIDC authentication enabled"
   # Retry messages mean Keycloak is not fully up yet - wait.
  ```
2. Open `http://localhost:3080`. You are redirected to the Keycloak login.
3. Log in with the test user; you are redirected back to Fail2Ban UI.
4. Verify the session: check the header for the user information and test the logout.

## Switching providers

### Pocket-ID instead of Keycloak

1. Stop the services: `podman compose down`
2. In `container-compose.yml`:
  - Comment out the `keycloak` and `postgres` services.
  - Uncomment the `pocket-id` service.
  - Update the fail2ban-ui environment:
    ```yaml
    - OIDC_PROVIDER=pocketid
    - OIDC_ISSUER_URL=http://localhost:3005
    - OIDC_LOGOUT_URL=http://localhost:3005/logout
    ```
  - Switch fail2ban-ui back to bridge networking (remove `network_mode: host`).
3. Start the services: `podman compose up -d`
4. Configure Pocket-ID: open `http://localhost:3005`, create the admin account, and create an OIDC client with redirect URI `http://localhost:3080/auth/callback`.

### Authentik instead of Keycloak

1. Stop the services: `podman compose down`
2. In `container-compose.yml`:
  - Comment out the `keycloak` and `postgres` services.
  - Uncomment all `authentik-*` services.
  - Update the fail2ban-ui environment:
    ```yaml
    - OIDC_PROVIDER=authentik
    - OIDC_ISSUER_URL=http://localhost:3007/application/o/fail2ban-ui/
    ```
  - Switch fail2ban-ui back to bridge networking (remove `network_mode: host`).
3. Start the services: `podman compose up -d`
4. Run the migrations:
  ```bash
   podman compose run --rm authentik-server migrate
  ```
5. Open the initial setup at `http://localhost:3007/if/flow/initial-setup/` and create the admin user.
6. In Authentik, create an OIDC provider and an application, and configure the client ID and secret.

## Configuration options

Edit `container-compose.yml` to customize the OIDC settings:

```yaml
environment:
  - OIDC_ENABLED=true                    # Enable/disable OIDC
  - OIDC_PROVIDER=keycloak               # keycloak, authentik, or pocketid
  - OIDC_ISSUER_URL=http://localhost:3000/realms/master  # Must match the provider's discovery document
  - OIDC_CLIENT_ID=fail2ban-ui
  - OIDC_CLIENT_SECRET=your-secret
  - OIDC_REDIRECT_URL=http://localhost:3080/auth/callback  # External URL for browser redirects
  - OIDC_SCOPES=openid,profile,email     # Comma-separated scopes
  - OIDC_SESSION_MAX_AGE=7200            # Session timeout in seconds
  - OIDC_USERNAME_CLAIM=preferred_username
  - OIDC_SKIP_VERIFY=true                # Skip TLS verification (development only)
```

**Note:** `OIDC_ISSUER_URL` must match the issuer returned by the provider's discovery document. For Keycloak with `KC_HOSTNAME=localhost`, that is `http://localhost:3000/realms/master`.

Provider-specific issuer URLs:


| Provider  | Issuer URL                                                   |
| --------- | ------------------------------------------------------------ |
| Keycloak  | `http://localhost:3000/realms/master` (or your custom realm) |
| Pocket-ID | `http://localhost:3005`                                      |
| Authentik | `http://localhost:3007/application/o/<client-slug>/`         |


## Troubleshooting

### Keycloak not accessible / health check failing

- Container running? `podman ps | grep keycloak`
- Health status: `podman inspect DEV_keycloak | grep -A 10 Health`
- Logs: `podman logs DEV_keycloak`
- Port mapping: `netstat -tlnp | grep 3000`
- The database must be ready first (its own health check).
- Keycloak needs 30-60 seconds; wait for "Keycloak started" in the logs.
- Keycloak 26+ serves health endpoints on port 9000:
  ```bash
  # From the host (if port 9000 is exposed):
  curl http://localhost:9000/health/ready

  # Or from inside the container:
  podman exec DEV_keycloak bash -c 'exec 3<>/dev/tcp/localhost/9000 && echo -e "GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3 && cat <&3'
  ```
- If the health check keeps failing although Keycloak runs, you can temporarily remove the `condition: service_healthy` from `depends_on` in `container-compose.yml` and let fail2ban-ui's retry logic handle the connection:
  ```yaml
  depends_on:
    - keycloak  # without condition: starts immediately
  ```

### fail2ban-ui fails to start / OIDC initialization errors

- **Container stuck in "Created" status.** It is waiting for Keycloak (`depends_on`). Check `podman compose ps` and the Keycloak logs. Either wait, start it manually with `podman start DEV_fail2ban-ui-oidc`, or temporarily remove the health condition as described above.
- **"Connection refused" errors.** Keycloak is not ready yet. The application retries automatically, up to 10 times with exponential backoff.
- **"Issuer did not match" errors.** `OIDC_ISSUER_URL` does not match the issuer in the discovery document. With `KC_HOSTNAME=localhost`, Keycloak returns `http://localhost:3000/realms/master` as the issuer. Verify:
  ```bash
  curl http://localhost:3000/realms/master/.well-known/openid-configuration | grep issuer
  ```
- **"Realm does not exist" errors.** The default configuration uses the `master` realm, which always exists. Check that `OIDC_ISSUER_URL` references an existing realm:
  ```bash
  curl http://localhost:3000/realms/master/.well-known/openid-configuration
  ```
- Detailed errors: `podman logs DEV_fail2ban-ui-oidc`.

### Authentication fails

1. Check the OIDC configuration: `OIDC_ISSUER_URL` matches the provider URL exactly; client ID and secret match the provider; the redirect URI matches exactly.
2. Check the application logs: `podman logs DEV_fail2ban-ui-oidc`.
3. Verify the provider client is active (Keycloak admin console at `http://localhost:3000`) and the redirect URI is exactly `http://localhost:3080/auth/callback`.

### Session issues

- Check that `OIDC_SESSION_SECRET` is set or auto-generated.
- Verify the session cookie settings; with `OIDC_SKIP_VERIFY=true` they work in the dev setup.
- Clear the browser cookies and try again.

### Keycloak realm not found

- The default setup uses the `master` realm, which always exists.
- For a custom realm, the name in `OIDC_ISSUER_URL` must match exactly (case-sensitive), and the realm must be enabled.
- Verify with `http://localhost:3000/realms/<realm-name>/.well-known/openid-configuration`.

## Cleanup

Remove all containers and volumes:

```bash
podman compose down -v
# or
docker-compose down -v
```

**Warning:** This deletes all development data, including the Keycloak database and the Fail2Ban UI configuration. Back up anything you want to keep first.

## Production considerations

This setup is for development only. For production:

- Use HTTPS/TLS, not HTTP.
- Set `OIDC_SKIP_VERIFY=false`.
- Use strong, randomly generated secrets, including the session secret.
- Put the UI behind a properly configured reverse proxy.
- Change the default admin passwords.
- Enable proper logging and monitoring.
- Use production-ready database configurations and a backup strategy.

