# Oktify CLI Usage Examples

This document provides extended examples and tips for using Oktify from the command line.

---

## Subcommands Overview

| Command  | Description                                  |
|----------|----------------------------------------------|
| `roles`  | Track user role ID changes                   |
| `users`  | Track user creation/suspension events        |
| `groups` | Track user group join/leave actions          |
| `apps`   | Track user app assignment/revocation actions |

All subcommands support these flags:
- `--start YYYY-MM-DD` – start date for filtering
- `--end YYYY-MM-DD` – end date for filtering
- `--output filename.csv` – optional CSV file name
- `--show` – also print results to terminal

---

## Install Locally as CLI
To install the tool globally for CLI access:
```
pip install -e .
```
Then invoke using:
```
oktify roles --start 2024-01-01 --end 2024-12-31 --show
```

---

## Example: Track Role Changes
```
oktify roles --start 2024-01-01 --end 2024-12-31 --output roles_audit.csv
```

## Example: Track Group Membership
```
oktify groups --start 2024-06-01 --end 2024-06-30 --show
```

## Example: User Lifecycle Events
```
oktify users --start 2024-01-01 --end 2024-03-31
```

## Example: App Assignment/Revocation
```
oktify apps --start 2024-07-01 --end 2024-07-31 --output july_apps.csv
```

---

## Notes
- Output filenames will auto-append a timestamp if none is provided.
- The `.env` file must be present with a valid Okta API domain and token.
- If you're running from source directly, use `python run.py` instead of `oktify`.

Enjoy!  
— KJB