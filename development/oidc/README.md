# OIDC Authentication Development Setup

This setup provides a complete OIDC authentication testing environment with Keycloak, Pocket-ID, and Authentik.

## Available OIDC Providers

### 1. Keycloak (Primary - Default)
- **Container:** `DEV_keycloak`
- **Port:** `3000` (mapped from internal `8080`)
- **Management Port:** `9000` (for health checks)
- **URL:** `http://localhost:3000`
- **Admin Console:** `http://localhost:3000`
- **Purpose:** Enterprise-grade OIDC provider (recommended)
- **Data:** Stored in `./keycloak-data/` and `./keycloak-db/`
- **Database:** PostgreSQL (container: `DEV_keycloak-db`)

### 2. Pocket-ID (Alternative 1)
- **Container:** `DEV_pocket-id` (commented out by default)
- **Port:** `3005` (when enabled)
- **URL:** `http://localhost:3005`
- **Purpose:** Lightweight OIDC provider with passkey support
- **Data:** Stored in `./pocket-id-data/`
- **Note:** Uncomment in `container-compose.yml` to use

### 3. Authentik (Alternative 2)
- **Containers:** `DEV_authentik-server`, `DEV_authentik-worker` (commented out by default)
- **Ports:** `3007` (HTTP), `3008` (HTTPS) (when enabled)
- **URL:** `http://localhost:3007`
- **Purpose:** Full-featured identity provider with OIDC support
- **Data:** Stored in `./authentik-media/` and `./authentik-db/`
- **Note:** Requires migrations and initial setup. Uncomment in `container-compose.yml` to use

### 4. Fail2ban-UI
- **Container:** `DEV_fail2ban-ui-oidc`
- **Port:** `3080`
- **URL:** `http://localhost:3080`
- **Purpose:** Main application with OIDC authentication enabled
- **OIDC Provider:** Keycloak (default, configurable)
- **Network:** Uses host network mode to access Keycloak on localhost

## Quick Start

**✅ Automatic Setup:** The OIDC client is automatically configured for Keycloak! Just start the containers and everything should work.

**Note:** All services bind to `0.0.0.0` for easy access from any network interface.

### For Remote Server Access

**Default Configuration:** The setup defaults to `localhost` for local development. For remote server access, you need to create a `.env` file with your server's IP address or hostname.

**Option 1: Using .env file (Recommended)**

1. Copy the example file:
   ```bash
   cd /opt/fail2ban-ui/development/oidc
   cp .env.example .env
   ```

2. Edit `.env` and update with your server's IP address or hostname:
   ```bash
   # Example: If your server IP is 172.16.10.18
   PUBLIC_FRONTEND_URL=http://172.16.10.18:3080
   KEYCLOAK_URL=http://172.16.10.18:3000
   KEYCLOAK_PUBLIC_URL=http://172.16.10.18:3000
   ```

3. Start containers (docker-compose/podman-compose will automatically load .env):
   ```bash
   podman compose up -d
   ```

**Option 2: Using environment variables**

```bash
# Set your server's IP address or hostname
export PUBLIC_FRONTEND_URL=http://YOUR_SERVER_IP:3080
export KEYCLOAK_URL=http://YOUR_SERVER_IP:3000
export KEYCLOAK_PUBLIC_URL=http://YOUR_SERVER_IP:3000

# Then start containers
cd /opt/fail2ban-ui/development/oidc
podman compose up -d
```

**Important:** 
- Without setting these, redirect URIs will use `localhost` which won't work from remote browsers
- After changing these values, you may need to recreate the Keycloak client to update redirect URIs:
  ```bash
  podman compose down
  rm -rf config/keycloak-client-secret
  podman compose up -d
  ```
  Or manually update the client in Keycloak admin console:
  - Go to Clients → fail2ban-ui (name of the client)
  - Update "Valid redirect URIs" and "Valid post logout redirect URIs"
  - Save

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
cd /opt/fail2ban-ui/development/oidc
podman compose up -d
# or
docker-compose up -d
```

**Important Notes:**
- **Keycloak startup time:** Keycloak takes 30-60 seconds to fully start. Be patient!
- **Container status:** The fail2ban-ui container will wait for Keycloak to start
- **If fail2ban-ui is stuck in "Created" status:**
  - Wait for Keycloak to show "healthy" status: `podman compose ps`
  - Or manually start fail2ban-ui: `podman start DEV_fail2ban-ui-oidc` (it will retry connecting)

### 3. Automatic Keycloak Client Configuration

**✅ Automatic:** The OIDC client is automatically created by the `keycloak-init` container. No manual configuration needed!

The `keycloak-init` container will:
- Wait for Keycloak to be ready
- Automatically create the `fail2ban-ui` OIDC client
- Configure redirect URIs and web origins
- Configure post-logout redirect URI (for proper logout flow)
- Save the client secret to `/config/keycloak-client-secret`
- Fail2ban-ui will automatically read the secret from this file

**Note:** If you update `PUBLIC_FRONTEND_URL` after the client has been created, you may need to delete the existing client and let `keycloak-init` recreate it, or manually update the client in Keycloak's admin console to include the new post-logout redirect URI.

**If you see "Client not found" error:**

This means the `keycloak-init` container hasn't run yet or failed. To fix:

1. **Check if Keycloak is running:**
   ```bash
   podman compose ps keycloak
   # Should show "healthy" status
   ```

2. **Run keycloak-init manually:**
   ```bash
   cd /opt/fail2ban-ui/development/oidc
   podman compose run --rm keycloak-init
   ```

3. **Verify the client secret was created:**
   ```bash
   ls -la config/keycloak-client-secret
   cat config/keycloak-client-secret
   ```

4. **Restart fail2ban-ui:**
   ```bash
   podman compose restart fail2ban-ui
   ```

**Manual Configuration (Alternative):**

If automatic configuration fails, you can manually create the client:

**Manual Setup Steps (if needed):**

1. **Wait for Keycloak to Start:**
   - Check logs: `podman logs DEV_keycloak`
   - Wait for "Keycloak started" message (may take 30-60 seconds)
   - Check container status: `podman compose ps` - Keycloak should show "healthy" status

2. **Access Keycloak Admin Console:**
   - Open `http://localhost:3000` in your browser (or use your host's IP address)
   - Login with:
     - **Username:** `admin`
     - **Password:** `admin`

3. **Select Realm:**
   - The default configuration uses the `master` realm (already selected)
   - **Optional:** Create a custom realm for production use (see below)

4. **Create OIDC Client (if auto-configuration failed):**
   - In the left sidebar, click **Clients**
   - Click **Create client** button (top right)
   - **Client ID:** Enter `fail2ban-ui` (must match `OIDC_CLIENT_ID` in container-compose.yml)
   - **Client protocol:** Select `openid-connect`
   - Click **Next**
   
   - **Client authentication:** Toggle **ON** (this makes it a confidential client)
   - **Authorization:** Leave OFF (unless you need it)
   - **Authentication flow:** Leave default settings
   - Click **Next**
   
   - **Login settings:**
     - **Root URL:** Leave empty
     - **Home URL:** Leave empty
     - **Valid redirect URIs:** Add `http://localhost:3080/auth/callback` (must match exactly)
     - **Valid post logout redirect URIs:** Leave empty
     - **Web origins:** Add `http://localhost:3080` (for CORS)
   - Click **Save**

5. **Get Client Secret (REQUIRED):**
   - After saving, you'll be on the client settings page
   - Click the **Credentials** tab
   - Copy the **Client secret** value (click "Copy" or manually copy)
   - **Update `container-compose.yml`:**
     ```bash
     # Edit the file
     nano /opt/fail2ban-ui/development/oidc/container-compose.yml
     # or
     vi /opt/fail2ban-ui/development/oidc/container-compose.yml
     ```
   - Find the line: `- OIDC_CLIENT_SECRET=change-me-secret`
   - Replace `change-me-secret` with the actual secret you copied
   - Save the file

6. **Restart fail2ban-ui:**
   ```bash
   podman compose restart fail2ban-ui
   ```

7. **Create a Test User (Optional but recommended):**
   - In Keycloak admin console, click **Users** in the left sidebar
   - Click **Create new user** button (top right)
   - **Username:** `testuser` (or any username)
   - **Email:** `test@example.com` (optional)
   - **Email verified:** Toggle ON (optional)
   - Click **Create**
   - Go to the **Credentials** tab
   - Click **Set password**
   - Enter a password
   - **Temporary:** Toggle OFF (so user doesn't need to reset password on first login)
   - Click **Save**

**Now you can access fail2ban-ui:**
- Open `http://localhost:3080` in your browser
- You should be redirected to Keycloak login
- Login with your test user credentials
- After successful authentication, you'll be redirected back to fail2ban-ui

**Optional: Create Custom Realm (for production):**

If you want to use a custom realm instead of `master`:

1. In Keycloak admin console, click the realm dropdown (top left, shows "master")
2. Click **Create Realm**
3. **Realm name:** Enter `myrealm` (or any name)
4. **Enabled:** Toggle ON
5. Click **Create**
6. **Update `container-compose.yml`:**
   ```yaml
   - OIDC_ISSUER_URL=http://localhost:3000/realms/myrealm
   ```
7. **Restart fail2ban-ui:**
   ```bash
   podman compose restart fail2ban-ui
   ```
8. **Create the OIDC client in the new realm** (follow steps 4-6 above)

### 4. Test Authentication

1. **Verify Fail2ban-UI Started Successfully:**
   - Check logs: `podman logs DEV_fail2ban-ui-oidc`
   - Look for: "OIDC authentication enabled" (should appear after Keycloak is ready)
   - If you see retry messages, wait a bit longer for Keycloak to fully start

2. **Access Fail2ban UI:**
   - Open `http://localhost:3080`
   - You should be redirected to Keycloak login

3. **Login:**
   - Use your Keycloak test user credentials
   - After successful authentication, you'll be redirected back to Fail2ban UI

4. **Verify Session:**
   - Check the header for your user information
   - Verify logout functionality

## Switching Between Providers

### Using Pocket-ID Instead of Keycloak

1. **Stop current services:**
   ```bash
   podman compose down
   ```

2. **Edit `container-compose.yml`:**
   - Comment out the `keycloak` and `postgres` services
   - Uncomment the `pocket-id` service
   - Update fail2ban-ui environment variables:
     ```yaml
     - OIDC_PROVIDER=pocketid
     - OIDC_ISSUER_URL=http://localhost:3005
     - OIDC_LOGOUT_URL=http://localhost:3005/logout
     ```
   - Change fail2ban-ui back to bridge network (remove `network_mode: host`)

3. **Start services:**
   ```bash
   podman compose up -d
   ```

4. **Configure Pocket-ID:**
   - Access `http://localhost:3005`
   - Create admin account
   - Create OIDC client with redirect URI: `http://localhost:3080/auth/callback`

### Using Authentik Instead of Keycloak

1. **Stop current services:**
   ```bash
   podman compose down
   ```

2. **Edit `container-compose.yml`:**
   - Comment out the `keycloak` and `postgres` services
   - Uncomment all `authentik-*` services
   - Update fail2ban-ui environment variables:
     ```yaml
     - OIDC_PROVIDER=authentik
     - OIDC_ISSUER_URL=http://localhost:3007/application/o/fail2ban-ui/
     ```
   - Change fail2ban-ui back to bridge network (remove `network_mode: host`)

3. **Start services:**
   ```bash
   podman compose up -d
   ```

4. **Run migrations and setup:**
   ```bash
   podman compose run --rm authentik-server migrate
   ```

5. **Access initial setup:**
   - Open `http://localhost:3007/if/flow/initial-setup/`
   - Create initial admin user

6. **Configure Authentik:**
   - Create OIDC Provider
   - Create Provider Application
   - Configure client ID and secret

## Configuration Options

### OIDC Environment Variables

Edit `container-compose.yml` to customize OIDC settings:

```yaml
environment:
  - OIDC_ENABLED=true                    # Enable/disable OIDC
  - OIDC_PROVIDER=keycloak               # Provider: keycloak, authentik, pocketid
  - OIDC_ISSUER_URL=http://localhost:3000/realms/master  # Must match provider's discovery document
  - OIDC_CLIENT_ID=fail2ban-ui
  - OIDC_CLIENT_SECRET=your-secret
  - OIDC_REDIRECT_URL=http://localhost:3080/auth/callback  # External URL for browser redirects
  - OIDC_SCOPES=openid,profile,email     # Comma-separated scopes
  - OIDC_SESSION_MAX_AGE=7200            # Session timeout (seconds)
  - OIDC_USERNAME_CLAIM=preferred_username
  - OIDC_SKIP_VERIFY=true                # Skip TLS verification (dev only)
```

**Note:** `OIDC_ISSUER_URL` must match the issuer returned by the provider's discovery document. For Keycloak with `KC_HOSTNAME=localhost`, use `http://localhost:3000/realms/master`.

### Provider-Specific Issuer URLs

- **Keycloak:** `http://localhost:3000/realms/master` (or your custom realm name)
- **Pocket-ID:** `http://localhost:3005`
- **Authentik:** `http://localhost:3007/application/o/<client-slug>/`

## Troubleshooting

### Keycloak Not Accessible / Healthcheck Failing

- Check if container is running: `podman ps | grep keycloak`
- Check container health status: `podman inspect DEV_keycloak | grep -A 10 Health`
- Check logs: `podman logs DEV_keycloak`
- Verify port mapping: `netstat -tlnp | grep 3000`
- Wait for database to be ready (healthcheck)
- Keycloak takes 30-60 seconds to fully start - wait for "Keycloak started" in logs
- **Healthcheck:** Keycloak v26+ uses port 9000 for health endpoints. Verify health endpoint:
  ```bash
  # From host (if port 9000 is exposed):
  curl http://localhost:9000/health/ready
  
  # Or test from inside container:
  podman exec DEV_keycloak bash -c 'exec 3<>/dev/tcp/localhost/9000 && echo -e "GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3 && cat <&3'
  ```
- **If healthcheck keeps failing:** You can temporarily modify `container-compose.yml` to remove the `condition: service_healthy` from `depends_on` and let fail2ban-ui's retry logic handle the connection:
  ```yaml
  depends_on:
    - keycloak  # Remove condition to start immediately
  ```

### Fail2ban-UI Fails to Start / OIDC Initialization Errors

- **Container stuck in "Created" status:**
  - This means it's waiting for Keycloak to start (via `depends_on`)
  - Check Keycloak status: `podman compose ps` - should show "healthy" when ready
  - Check Keycloak logs: `podman logs DEV_keycloak`
  - If Keycloak healthcheck is failing but Keycloak is running, you can:
    1. Wait longer (Keycloak takes 30-60 seconds to start)
    2. Manually start fail2ban-ui: `podman start DEV_fail2ban-ui-oidc` (it will retry connecting)
    3. Temporarily remove `condition: service_healthy` from `depends_on` in `container-compose.yml`

- **"Connection refused" errors:** Keycloak isn't ready yet. The application will retry automatically (up to 10 times with exponential backoff). Wait for Keycloak to fully start (30-60 seconds).

- **"Issuer did not match" errors:**
  - This happens when `OIDC_ISSUER_URL` doesn't match the issuer in Keycloak's discovery document
  - Keycloak is configured with `KC_HOSTNAME=localhost`, so it returns `http://localhost:3000/realms/master` as issuer
  - Ensure `OIDC_ISSUER_URL` is set to: `http://localhost:3000/realms/master` (or your custom realm)
  - Verify the issuer: `curl http://localhost:3000/realms/master/.well-known/openid-configuration | grep issuer`

- **"Realm does not exist" errors:** 
  - The default configuration uses the `master` realm which always exists
  - If you see this error, check that `OIDC_ISSUER_URL` in `container-compose.yml` matches an existing realm
  - Verify the realm exists: `curl http://localhost:3000/realms/master/.well-known/openid-configuration`
  - Or access Keycloak admin console and check available realms

- **Check fail2ban-ui logs:** `podman logs DEV_fail2ban-ui-oidc` for detailed error messages
- **Check Keycloak is ready:** Wait for log message "Keycloak ... started" and verify health endpoint responds

### Authentication Fails

1. **Check OIDC Configuration:**
   - Verify `OIDC_ISSUER_URL` matches provider URL exactly
   - Ensure client ID and secret match provider configuration
   - Check redirect URI matches exactly

2. **Check Fail2ban-UI Logs:**
   ```bash
   podman logs DEV_fail2ban-ui-oidc
   ```

3. **Verify Provider Client:**
   - Ensure client is active in provider admin (accessible at `http://localhost:3000` for Keycloak)
   - Check redirect URI is exactly: `http://localhost:3080/auth/callback`

### Session Issues

- Check `OIDC_SESSION_SECRET` is set (or auto-generated)
- Verify session cookie settings (should work with `OIDC_SKIP_VERIFY=true` in dev)
- Clear browser cookies and try again

### Keycloak Realm Not Found

- **Default Configuration:** The setup uses the `master` realm by default. This realm always exists in Keycloak.
- **Custom Realm:** If you created a custom realm (e.g., `myrealm`), ensure:
  - The realm name in `OIDC_ISSUER_URL` matches exactly (case-sensitive)
  - The realm is enabled in Keycloak admin console
  - Update `OIDC_ISSUER_URL` in `container-compose.yml` to: `http://localhost:3000/realms/myrealm`
- **Check Realm:** Access `http://localhost:3000/realms/<realm-name>/.well-known/openid-configuration` to verify the realm exists

## Cleanup

To remove all containers and volumes:

```bash
podman compose down -v
# or
docker-compose down -v
```

This will remove:
- All containers
- Volume data (Keycloak database, Fail2ban-UI config, etc.)

**Note:** This deletes all development data. Make sure to backup anything important.

## Production Considerations

⚠️ **This setup is for development only!**

For production:
- Use HTTPS/TLS (not HTTP)
- Set `OIDC_SKIP_VERIFY=false`
- Use strong, randomly generated secrets
- Configure proper reverse proxy
- Use secure session secrets
- Change default admin passwords
- Enable proper logging and monitoring
- Use production-ready database configurations
- Configure proper backup strategies
