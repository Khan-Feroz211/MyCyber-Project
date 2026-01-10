#!/bin/bash

# Quick Update Script for CyberShield Live Repository
# Use this to quickly push changes to GitHub

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   CyberShield - Quick Update          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

cd ~/dlp_clean_final

# Check for changes
echo -e "${YELLOW}Checking for changes...${NC}"
if [[ -z $(git status -s) ]]; then
    echo -e "${GREEN}No changes to commit${NC}"
    exit 0
fi

# Show what changed
echo ""
echo -e "${YELLOW}Changes detected:${NC}"
git status -s

# Ask for commit message
echo ""
echo -e "${YELLOW}Enter commit message (or press Enter for default):${NC}"
read -p "> " commit_msg

if [ -z "$commit_msg" ]; then
    commit_msg="Update: Minor changes and improvements"
fi

# Add, commit, push
echo ""
echo -e "${BLUE}Adding files...${NC}"
git add .

echo -e "${BLUE}Committing changes...${NC}"
git commit -m "$commit_msg"

echo -e "${BLUE}Pushing to GitHub...${NC}"
git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   ✓ Successfully updated GitHub!      ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}View your changes at:${NC}"
    echo "https://github.com/Khan-Feroz211/MyCyber-Project"
    echo ""
else
    echo ""
    echo -e "${RED}✗ Push failed${NC}"
    exit 1
fi
