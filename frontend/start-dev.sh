#!/bin/bash
export PATH="/Users/aadamshaik/.nvm/versions/node/v24.14.1/bin:$PATH"
cd "$(dirname "$0")"
exec npm run dev
