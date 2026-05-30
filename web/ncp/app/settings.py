from db import execute, fetch_one


def setting_enabled(key):
    row = fetch_one("SELECT value FROM settings WHERE key = ?", (key,))
    return row["value"] == "1" if row else False


def set_asset_storage_enabled(enabled):
    execute(
        "UPDATE settings SET value = ? WHERE key = ?",
        ("1" if enabled else "0", "asset_storage_enabled"),
    )
