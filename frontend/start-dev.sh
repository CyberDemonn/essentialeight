#!/bin/bash
# Add nvm node to PATH if nvm is installed
if [ -s "$HOME/.nvm/nvm.sh" ]; then
  export NVM_DIR="$HOME/.nvm"
  # shellcheck source=/dev/null
  . "$NVM_DIR/nvm.sh"
fi
cd "$(dirname "$0")"
exec npm run dev
