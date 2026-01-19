#!/bin/bash
# Automatic Keycloak OIDC client configuration script
# This script creates the fail2ban-ui OIDC client in Keycloak automatically

set -e

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:3000}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_PASSWORD="${KEYCLOAK_PASSWORD:-admin}"
REALM="${REALM:-master}"
CLIENT_ID="${CLIENT_ID:-fail2ban-ui}"
CLIENT_SECRET="${CLIENT_SECRET:-}"
# Use PUBLIC_FRONTEND_URL if provided, otherwise default to localhost
PUBLIC_FRONTEND_URL="${PUBLIC_FRONTEND_URL:-http://localhost:3080}"
REDIRECT_URI="${REDIRECT_URI:-${PUBLIC_FRONTEND_URL}/auth/callback}"
POST_LOGOUT_REDIRECT_URI="${POST_LOGOUT_REDIRECT_URI:-${PUBLIC_FRONTEND_URL}/auth/login}"
WEB_ORIGIN="${WEB_ORIGIN:-${PUBLIC_FRONTEND_URL}}"

# Extract host and port from KEYCLOAK_URL for health check
# KEYCLOAK_URL is the internal URL (e.g., http://keycloak:8080)
# Health endpoint is on management port 9000
KEYCLOAK_HOST=$(echo "${KEYCLOAK_URL}" | sed -E 's|https?://([^:/]+).*|\1|')
KEYCLOAK_HEALTH_URL="http://${KEYCLOAK_HOST}:9000/health/ready"

echo "Waiting for Keycloak to be ready..."
echo "Checking health endpoint: ${KEYCLOAK_HEALTH_URL}"
max_attempts=120  # Increased timeout since Keycloak can take a while
attempt=0
while [ $attempt -lt $max_attempts ]; do
    # Check health endpoint on management port 9000
    if curl -s -f "${KEYCLOAK_HEALTH_URL}" > /dev/null 2>&1; then
        echo "Keycloak is ready!"
        break
    fi
    # Also try the main port as fallback
    if curl -s -f "${KEYCLOAK_URL}/health/ready" > /dev/null 2>&1; then
        echo "Keycloak is ready (via main port)!"
        break
    fi
    attempt=$((attempt + 1))
    if [ $((attempt % 10)) -eq 0 ]; then
        echo "Attempt $attempt/$max_attempts: Keycloak not ready yet, waiting..."
    fi
    sleep 2
done

if [ $attempt -eq $max_attempts ]; then
    echo "ERROR: Keycloak did not become ready in time"
    exit 1
fi

echo "Waiting for Keycloak admin API to be available..."
sleep 5

echo "Getting admin access token..."
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${KEYCLOAK_ADMIN}" \
    -d "password=${KEYCLOAK_PASSWORD}" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" | jq -r '.access_token')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
    echo "ERROR: Failed to get admin token"
    exit 1
fi

echo "Checking if client already exists..."
EXISTING_CLIENT=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/clients?clientId=${CLIENT_ID}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" | jq -r '.[0].id // empty')

if [ -n "$EXISTING_CLIENT" ]; then
    echo "Client '${CLIENT_ID}' already exists, updating..."
    CLIENT_UUID="$EXISTING_CLIENT"
    
    # Update client configuration
    curl -s -X PUT "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${CLIENT_UUID}" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"clientId\": \"${CLIENT_ID}\",
            \"enabled\": true,
            \"clientAuthenticatorType\": \"client-secret\",
            \"redirectUris\": [\"${REDIRECT_URI}\"],
            \"webOrigins\": [\"${WEB_ORIGIN}\"],
            \"attributes\": {
                \"post.logout.redirect.uris\": \"${POST_LOGOUT_REDIRECT_URI}\"
            },
            \"protocol\": \"openid-connect\",
            \"publicClient\": false,
            \"standardFlowEnabled\": true,
            \"directAccessGrantsEnabled\": true
        }" > /dev/null
    
    echo "Client updated successfully"
else
    echo "Creating new client '${CLIENT_ID}'..."
    
    # Create client
    CLIENT_RESPONSE=$(curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/clients" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"clientId\": \"${CLIENT_ID}\",
            \"enabled\": true,
            \"clientAuthenticatorType\": \"client-secret\",
            \"redirectUris\": [\"${REDIRECT_URI}\"],
            \"webOrigins\": [\"${WEB_ORIGIN}\"],
            \"attributes\": {
                \"post.logout.redirect.uris\": \"${POST_LOGOUT_REDIRECT_URI}\"
            },
            \"protocol\": \"openid-connect\",
            \"publicClient\": false,
            \"standardFlowEnabled\": true,
            \"directAccessGrantsEnabled\": true
        }")
    
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to create client"
        exit 1
    fi
    
    # Get the client UUID
    CLIENT_UUID=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/clients?clientId=${CLIENT_ID}" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" | jq -r '.[0].id')
    
    echo "Client created successfully with UUID: ${CLIENT_UUID}"
fi

# Get or regenerate client secret
echo "Getting client secret..."
CLIENT_SECRET=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${CLIENT_UUID}/client-secret" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" | jq -r '.value')

if [ -z "$CLIENT_SECRET" ] || [ "$CLIENT_SECRET" = "null" ]; then
    echo "Regenerating client secret..."
    CLIENT_SECRET=$(curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${CLIENT_UUID}/client-secret" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" | jq -r '.value')
fi

if [ -z "$CLIENT_SECRET" ] || [ "$CLIENT_SECRET" = "null" ]; then
    echo "ERROR: Failed to get client secret"
    exit 1
fi

echo ""
echo "=========================================="
echo "OIDC Client Configuration Complete!"
echo "=========================================="
echo "Client ID: ${CLIENT_ID}"
echo "Client Secret: ${CLIENT_SECRET}"
echo "Realm: ${REALM}"
echo "Redirect URI: ${REDIRECT_URI}"
echo "Post Logout Redirect URI: ${POST_LOGOUT_REDIRECT_URI}"
echo "=========================================="

# Save secret to shared volume for fail2ban-ui to read
SECRET_FILE="${SECRET_FILE:-/config/keycloak-client-secret}"
# Create directory if it doesn't exist
mkdir -p "$(dirname "${SECRET_FILE}")" 2>/dev/null || true
# Write secret file (running as root, so should have permissions)
if echo "${CLIENT_SECRET}" > "${SECRET_FILE}" 2>/dev/null; then
    chmod 644 "${SECRET_FILE}" 2>/dev/null || true
    echo "Client secret saved to ${SECRET_FILE} for fail2ban-ui"
else
    echo "ERROR: Failed to write client secret to ${SECRET_FILE}"
    echo "Client secret: ${CLIENT_SECRET}"
    echo "Please save this secret manually to ${SECRET_FILE}"
    exit 1
fi
