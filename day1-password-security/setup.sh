#!/bin/bash

# Backend Course Series - Day 1 Setup Script
# This script helps you get started quickly

echo "🚀 Backend Course Series - Day 1: Password Security"
echo "=================================================="
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed!"
    echo "   Please install Node.js from https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node -v)
echo "✅ Node.js $NODE_VERSION detected"
echo ""

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed!"
    exit 1
fi

NPM_VERSION=$(npm -v)
echo "✅ npm $NPM_VERSION detected"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
npm install

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully!"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo ""
echo "🎉 Setup complete! You're ready to start learning."
echo ""
echo "📚 Quick Start Commands:"
echo "  npm run example:basic    - Basic bcrypt demo"
echo "  npm run example:api      - Express authentication API"
echo "  npm run example:strength - Password strength validator"
echo "  npm run example:argon2   - Argon2 algorithm demo"
echo "  npm run example:timing   - Timing attack prevention"
echo "  npm run example:migration- Password migration strategies"
echo "  npm test                 - Run security tests"
echo ""
echo "📖 Read the QUICKSTART.md for detailed instructions"
echo ""
echo "Happy learning! 🚀"
