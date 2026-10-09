"""
Sentinel Stream — bootstrap admin user.

Creates the first admin user for a fresh deployment. Run once after install.

Usage:
    python -m sentinel.bootstrap-admin --user-id admin --tenant-id default --name "SOC Admin"
    # → prints API key (save it — shown once)
"""
from __future__ import annotations

import argparse
import sys

from sentinel.rbac import Role, get_rbac


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap first admin user")
    parser.add_argument("--user-id", required=True, help="Unique user ID (e.g. 'admin')")
    parser.add_argument("--tenant-id", required=True, help="Tenant ID (e.g. 'default' or 'acme')")
    parser.add_argument("--name", default="", help="Display name")
    parser.add_argument("--email", default="", help="Email address")
    args = parser.parse_args()

    rbac = get_rbac()
    api_key = rbac.create_user(
        user_id=args.user_id,
        role=Role.ADMIN,
        tenant_id=args.tenant_id,
        name=args.name,
        email=args.email,
    )
    print("=" * 60)
    print("✓ Admin user created successfully")
    print(f"  User ID:   {args.user_id}")
    print(f"  Tenant:    {args.tenant_id}")
    print(f"  Role:      admin")
    print(f"  API Key:   {api_key}")
    print("=" * 60)
    print("⚠️  SAVE THIS KEY — it will not be shown again.")
    print("    Set as X-API-Key header for all API requests.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
