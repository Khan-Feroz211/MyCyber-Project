#!/bin/bash

# Quick Git Push Script for CyberShield
# This script helps you quickly push your code to GitHub

echo "╔════════════════════════════════════════╗"
echo "║   CyberShield - Quick Git Push        ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo -e "${YELLOW}Git not initialized. Initializing...${NC}"
    git init
    echo -e "${GREEN}✓ Git initialized${NC}"
fi

# Check if remote exists
if ! git remote get-url origin > /dev/null 2>&1; then
    echo -e "${YELLOW}Adding remote repository...${NC}"
    git remote add origin https://github.com/Khan-Feroz211/MyCyber-Project.git
    echo -e "${GREEN}✓ Remote added${NC}"
fi

# Show current status
echo ""
echo "Current repository status:"
git status --short

# Ask for commit message
echo ""
echo -e "${YELLOW}Enter commit message (or press Enter for default):${NC}"
read -p "> " commit_message

if [ -z "$commit_message" ]; then
    commit_message="Update: Push changes to repository"
fi

# Add all files
echo ""
echo "Adding files..."
git add .

# Show what will be committed
echo ""
echo "Files to be committed:"
git diff --cached --name-status

# Commit
echo ""
echo "Committing changes..."
git commit -m "$commit_message"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Changes committed${NC}"
else
    echo -e "${RED}✗ Commit failed${NC}"
    exit 1
fi

# Ensure we're on main branch
current_branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$current_branch" != "main" ]; then
    echo ""
    echo "Switching to main branch..."
    git branch -M main
fi

# Push to GitHub
echo ""
echo "Pushing to GitHub..."
git push -u origin main

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   ✓ Successfully pushed to GitHub!    ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo "View your repository at:"
    echo "https://github.com/Khan-Feroz211/MyCyber-Project"
else
    echo ""
    echo -e "${RED}✗ Push failed${NC}"
    echo ""
    echo "Common solutions:"
    echo "1. Check your internet connection"
    echo "2. Verify GitHub credentials"
    echo "3. Make sure you have push access"
    echo "4. Try: git push -u origin main --force"
    exit 1
fi
