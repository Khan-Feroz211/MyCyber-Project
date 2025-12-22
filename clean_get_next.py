def get_next_user_id():
    """Get the next available user ID"""
    users = load_users()
    if users:
        # Get all user IDs - handle both string and integer keys
        user_ids = []
        for uid in users:
            if isinstance(uid, int):
                user_ids.append(uid)
            elif isinstance(uid, str) and uid.isdigit():
                user_ids.append(int(uid))
            else:
                try:
                    user_ids.append(int(uid))
                except (ValueError, TypeError):
                    continue
        if user_ids:
            return max(user_ids) + 1
    return 1
