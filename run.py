#
#  ██████╗ ██╗  ██╗████████╗██╗███████╗██╗   ██╗
#  ██╔══██╗██║  ██║╚══██╔══╝██║██╔════╝╚██╗ ██╔╝
#  ██████╔╝███████║   ██║   ██║█████╗   ╚████╔╝ 
#  ██╔═══╝ ██╔══██║   ██║   ██║██╔══╝    ╚██╔╝  
#  ██║     ██║  ██║   ██║   ██║███████╗   ██║   
#  ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝╚══════╝   ╚═╝   
#
#  Oktify: A CLI tool for tracking Okta changes
#  https://github.com/kevinjbeattie/oktify
#

"""
Oktify – run.py

Main entrypoint for the Oktify CLI tool. Supports the following subcommands:
  - roles: Track role ID changes
  - users: Track user creation and suspension events
  - groups: Track group membership changes (join/leave)
  - apps: Track app assignment or revocation actions

Arguments:
  --start YYYY-MM-DD   Required. Start of date filter range.
  --end YYYY-MM-DD     Required. End of date filter range.
  --output             Optional. Custom output filename.
  --show               Optional. Display output in terminal.

Each subcommand fetches users from the Okta API, parses relevant changes,
and exports the filtered results to a timestamped CSV file.
"""

import argparse
import warnings
from datetime import datetime
from urllib3.exceptions import NotOpenSSLWarning
from okta_utils import (
    get_all_users,
    parse_role_changes,
    export_role_changes_to_csv,
    parse_user_lifecycle_changes,
    parse_group_membership_changes,
    parse_app_assignments
)

# Suppress OpenSSL warning if present
warnings.filterwarnings("ignore", category=NotOpenSSLWarning)

# Shared date parsing logic
def parse_date_range(args):
    try:
        start_date = datetime.strptime(args.start, "%Y-%m-%d").date()
        end_date = datetime.strptime(args.end, "%Y-%m-%d").date()
        if end_date < start_date:
            print("❌ End date must be after start date.")
            exit(1)
        return start_date, end_date
    except ValueError as ve:
        print(f"❌ Invalid date format: {ve}")
        exit(1)

# Subcommand: roles
def handle_roles(args):
    start_date, end_date = parse_date_range(args)
    print("🔄 Fetching users from Okta...")
    users = get_all_users()

    if not users:
        print("⚠️ No users returned from Okta API.")
        exit(1)

    print(f"✅ Retrieved {len(users)} user(s). Parsing role changes between {start_date} and {end_date}...")
    role_changes = parse_role_changes(users, start_date, end_date)

    if role_changes:
        print(f"✅ Found {len(role_changes)} role change(s). Exporting to CSV...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = args.output or f"role_changes_{timestamp}.csv"
        export_role_changes_to_csv(role_changes, filename=filename)

        if args.show:
            for rc in role_changes:
                print(rc)
    else:
        print("ℹ️ No role changes found in the given time period.")

# Subcommand: users
def handle_users(args):
    start_date, end_date = parse_date_range(args)
    print("🔄 Fetching users from Okta...")
    users = get_all_users()

    if not users:
        print("⚠️ No users returned from Okta API.")
        exit(1)

    print(f"✅ Retrieved {len(users)} user(s). Parsing user creation/suspension events...")
    lifecycle_events = parse_user_lifecycle_changes(users, start_date, end_date)

    if lifecycle_events:
        print(f"✅ Found {len(lifecycle_events)} user lifecycle event(s). Exporting to CSV...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = args.output or f"user_lifecycle_{timestamp}.csv"
        export_role_changes_to_csv(lifecycle_events, filename=filename)

        if args.show:
            for event in lifecycle_events:
                print(event)
    else:
        print("ℹ️ No user lifecycle events found in the given time period.")

# Subcommand: groups
def handle_groups(args):
    start_date, end_date = parse_date_range(args)
    print("🔄 Fetching users from Okta...")
    users = get_all_users()

    if not users:
        print("⚠️ No users returned from Okta API.")
        exit(1)

    print(f"✅ Retrieved {len(users)} user(s). Parsing group membership changes...")
    group_changes = parse_group_membership_changes(users, start_date, end_date)

    if group_changes:
        print(f"✅ Found {len(group_changes)} group membership change(s). Exporting to CSV...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = args.output or f"group_changes_{timestamp}.csv"
        export_role_changes_to_csv(group_changes, filename=filename)

        if args.show:
            for change in group_changes:
                print(change)
    else:
        print("ℹ️ No group membership changes found in the given time period.")

# Subcommand: apps
def handle_apps(args):
    start_date, end_date = parse_date_range(args)
    print("🔄 Fetching users from Okta...")
    users = get_all_users()

    if not users:
        print("⚠️ No users returned from Okta API.")
        exit(1)

    print(f"✅ Retrieved {len(users)} user(s). Parsing app assignments...")
    app_changes = parse_app_assignments(users, start_date, end_date)

    if app_changes:
        print(f"✅ Found {len(app_changes)} app assignment change(s). Exporting to CSV...")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = args.output or f"app_changes_{timestamp}.csv"
        export_role_changes_to_csv(app_changes, filename=filename)

        if args.show:
            for change in app_changes:
                print(change)
    else:
        print("ℹ️ No app assignment changes found in the given time period.")

# CLI setup
def main():
    parser = argparse.ArgumentParser(description="Oktify: Track and audit Okta changes from the command line.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # roles command
    roles_parser = subparsers.add_parser("roles", help="List user role changes in a given date range")
    roles_parser.add_argument("--start", required=True, help="Start date (YYYY-MM-DD)")
    roles_parser.add_argument("--end", required=True, help="End date (YYYY-MM-DD)")
    roles_parser.add_argument("--output", help="Optional output filename")
    roles_parser.add_argument("--show", action="store_true", help="Also print results to terminal")
    roles_parser.set_defaults(func=handle_roles)

    # users command
    users_parser = subparsers.add_parser("users", help="Track user creation and suspension events")
    users_parser.add_argument("--start", required=True, help="Start date (YYYY-MM-DD)")
    users_parser.add_argument("--end", required=True, help="End date (YYYY-MM-DD)")
    users_parser.add_argument("--output", help="Optional output filename")
    users_parser.add_argument("--show", action="store_true", help="Also print results to terminal")
    users_parser.set_defaults(func=handle_users)

    # groups command
    groups_parser = subparsers.add_parser("groups", help="Track group membership changes")
    groups_parser.add_argument("--start", required=True, help="Start date (YYYY-MM-DD)")
    groups_parser.add_argument("--end", required=True, help="End date (YYYY-MM-DD)")
    groups_parser.add_argument("--output", help="Optional output filename")
    groups_parser.add_argument("--show", action="store_true", help="Also print results to terminal")
    groups_parser.set_defaults(func=handle_groups)

    # apps command
    apps_parser = subparsers.add_parser("apps", help="Track user app assignments or revocations")
    apps_parser.add_argument("--start", required=True, help="Start date (YYYY-MM-DD)")
    apps_parser.add_argument("--end", required=True, help="End date (YYYY-MM-DD)")
    apps_parser.add_argument("--output", help="Optional output filename")
    apps_parser.add_argument("--show", action="store_true", help="Also print results to terminal")
    apps_parser.set_defaults(func=handle_apps)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()