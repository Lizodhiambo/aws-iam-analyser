import boto3
import os
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from botocore.exceptions import NoCredentialsError, ClientError

# Load credentials from .env file
load_dotenv()

console = Console()


def create_iam_client():
    """
    Create and return a boto3 IAM client.
    Credentials are loaded from environment variables (via .env).
    """
    try:
        client = boto3.client(
            "iam",
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=os.getenv("AWS_DEFAULT_REGION"),
        )
        return client
    except Exception as e:
        console.print(f"[red]Failed to create IAM client: {e}[/red]")
        raise


def verify_connection(iam_client):
    """
    Verify that credentials work by calling get_account_summary().
    This is a lightweight call that confirms auth is working.
    """
    try:
        response = iam_client.get_account_summary()
        summary = response["SummaryMap"]
        console.print("[green]✓ Successfully connected to AWS IAM[/green]\n")

        # Print a few key account stats
        table = Table(title="Account Summary", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="dim")
        table.add_column("Count", justify="right")

        table.add_row("Users", str(summary.get("Users", 0)))
        table.add_row("Groups", str(summary.get("Groups", 0)))
        table.add_row("Roles", str(summary.get("Roles", 0)))
        table.add_row("Policies (customer managed)", str(summary.get("Policies", 0)))
        table.add_row("MFA devices", str(summary.get("MFADevices", 0)))
        table.add_row("Access keys", str(summary.get("AccessKeysPerUserQuota", 0)))

        console.print(table)

    except NoCredentialsError:
        console.print("[red]✗ No credentials found. Check your .env file.[/red]")
        raise
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        console.print(f"[red]✗ AWS error: {error_code} — {e.response['Error']['Message']}[/red]")
        raise


def list_iam_users(iam_client):
    """
    List all IAM users in the account.
    Uses a paginator so it handles accounts with 100+ users automatically.
    """
    console.print("\n[bold]IAM Users[/bold]")

    paginator = iam_client.get_paginator("list_users")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Username")
    table.add_column("User ID", style="dim")
    table.add_column("Created")
    table.add_column("Password last used")

    user_count = 0

    for page in paginator.paginate():
        for user in page["Users"]:
            user_count += 1
            password_last_used = user.get("PasswordLastUsed", "Never / no console access")
            if hasattr(password_last_used, "strftime"):
                password_last_used = password_last_used.strftime("%Y-%m-%d")

            table.add_row(
                user["UserName"],
                user["UserId"],
                user["CreateDate"].strftime("%Y-%m-%d"),
                str(password_last_used),
            )

    console.print(table)
    console.print(f"[dim]Total users: {user_count}[/dim]")


def list_iam_roles(iam_client):
    """
    List all IAM roles in the account.
    Roles are used by services and applications — a common attack surface.
    """
    console.print("\n[bold]IAM Roles[/bold]")

    paginator = iam_client.get_paginator("list_roles")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Role name")
    table.add_column("Created")
    table.add_column("Description")

    role_count = 0

    for page in paginator.paginate():
        for role in page["Roles"]:
            role_count += 1
            table.add_row(
                role["RoleName"],
                role["CreateDate"].strftime("%Y-%m-%d"),
                role.get("Description", "—")[:60],  # truncate long descriptions
            )

    console.print(table)
    console.print(f"[dim]Total roles: {role_count}[/dim]")


def list_customer_managed_policies(iam_client):
    """
    List all customer-managed IAM policies.
    These are the policies YOUR team wrote — most likely to have misconfigurations.
    AWS-managed policies are excluded (they are generally safe).
    """
    console.print("\n[bold]Customer-managed policies[/bold]")

    paginator = iam_client.get_paginator("list_policies")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Policy name")
    table.add_column("Attached to")
    table.add_column("Created")

    policy_count = 0

    # Scope=Local filters to customer-managed only (excludes AWS-managed)
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            policy_count += 1
            table.add_row(
                policy["PolicyName"],
                str(policy["AttachmentCount"]) + " entities",
                policy["CreateDate"].strftime("%Y-%m-%d"),
            )

    console.print(table)
    console.print(f"[dim]Total customer-managed policies: {policy_count}[/dim]")
    console.print(
        "[dim]Note: AWS-managed policies excluded — they are audited by AWS.[/dim]"
    )


def main():
    console.print("[bold cyan]AWS IAM Analyser — Phase 1: Connection & Discovery[/bold cyan]\n")

    # Step 1: Create client
    iam = create_iam_client()

    # Step 2: Verify credentials work
    verify_connection(iam)

    # Step 3: List users, roles, policies
    list_iam_users(iam)
    list_iam_roles(iam)
    list_customer_managed_policies(iam)

    console.print(
        "\n[green]Phase 1 complete.[/green] "
        "You now have a live inventory of your IAM environment.\n"
        "Next: Phase 2 — scan these for misconfigurations.\n"
    )


if __name__ == "__main__":
    main()
