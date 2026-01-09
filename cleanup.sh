#!/bin/bash

echo "🚀 Cleaning DLP project for GitHub..."

# Create backup of important files
mkdir -p .backup
cp -r databases .backup/
cp -r reports .backup/
cp -r logs .backup/
cp config/settings.py .backup/

# Remove all backup and temporary files
find . -name "*.backup*" -type f -delete
find . -name "*.bak" -type f -delete
find . -name "*_backup" -type f -delete
find . -name "*~" -type f -delete
find . -name "*.pyc" -type f -delete
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
find . -name "*.log" -size +10M -delete

# Remove specific problematic files
rm -f app.py.backup_before_final_fix \
      app.py.backup_before_fix \
      app.py.backup_final \
      app.py.bak \
      app.py.before_final_fix \
      app.py.flask_backup \
      apply_correct_fix.py \
      clean_get_next.py \
      clean_version.py \
      create_dlp_databases.py \
      create_fixed_app.py \
      find_dict_access.py \
      fix_functions.py \
      fix_get_next_user_id.py \
      fix_save_new_user.py \
      fix_secrets.sh \
      test_fixed_registration.py \
      test_registration.py

# Clean empty directories
find . -type d -empty -delete

echo "✅ Cleanup complete!"
