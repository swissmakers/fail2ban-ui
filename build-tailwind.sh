#!/bin/bash
# Builds pkg/web/static/tailwind.css with the latest Tailwind CSS v3.

set -e

echo "Building Tailwind CSS v3 for Fail2ban-UI..."

if ! command -v node &> /dev/null; then
    echo "Error: Node.js is not installed. Please install Node.js first."
    echo "Visit: https://nodejs.org/"
    exit 1
fi

if ! command -v npm &> /dev/null; then
    echo "Error: npm is not installed. Please install npm first."
    exit 1
fi

mkdir -p pkg/web/static
mkdir -p .tailwind-build

if [ ! -f package.json ]; then
    echo "Initializing npm package..."
    npm init -y --silent
fi

echo "Installing latest Tailwind CSS v3..."
npm install -D tailwindcss@^3 --silent

if [ ! -f "node_modules/.bin/tailwindcss" ] && [ ! -f "node_modules/tailwindcss/lib/cli.js" ]; then
    echo "Error: Tailwind CSS CLI not found after installation."
    exit 1
fi

INSTALLED_VERSION=$(npm list tailwindcss 2>/dev/null | grep "tailwindcss@" | head -1 | awk '{print $2}' || echo "unknown")
echo "Installed: $INSTALLED_VERSION"

if [ ! -f tailwind.config.js ]; then
    echo "Creating Tailwind CSS configuration..."
    cat > tailwind.config.js << 'EOF'
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./pkg/web/templates/**/*.html",
    "./pkg/web/static/js/**/*.js",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
EOF
fi

if [ ! -f .tailwind-build/input.css ]; then
    echo "Creating input CSS file..."
    cat > .tailwind-build/input.css << 'EOF'
@tailwind base;
@tailwind components;
@tailwind utilities;
EOF
fi

echo "Building Tailwind CSS..."

if [ -f "node_modules/.bin/tailwindcss" ]; then
    node_modules/.bin/tailwindcss -i .tailwind-build/input.css -o pkg/web/static/tailwind.css --minify
elif [ -f "node_modules/tailwindcss/lib/cli.js" ]; then
    node node_modules/tailwindcss/lib/cli.js -i .tailwind-build/input.css -o pkg/web/static/tailwind.css --minify
elif command -v npx &> /dev/null; then
    npx --yes tailwindcss -i .tailwind-build/input.css -o pkg/web/static/tailwind.css --minify
else
    echo "Error: Could not find Tailwind CSS CLI"
    exit 1
fi

if [ ! -f "pkg/web/static/tailwind.css" ] || [ ! -s "pkg/web/static/tailwind.css" ]; then
    echo "Error: Output file was not created or is empty"
    exit 1
fi

echo "Tailwind CSS v3 built successfully."
echo "Output: pkg/web/static/tailwind.css"
echo ""
echo "The application will now use the local Tailwind CSS file instead of the CDN."
