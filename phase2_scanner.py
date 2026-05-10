import boto3
import os
import json
from datetime import datetime, timezone
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from botocore.exceptions import ClientError

# Load credentials from environment
load_dotenv()

console = Console()

# ─── Severity colours for the terminal ───────────────────────────────────────
SEVERITY_COLOUR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold cyan",
}

findings = []   # all findings are collected here


def add_finding(severity, category, resource, issue, recommendation):
    """Store a single finding and print it immediately."""
    findings.append({
        "severity":       severity,
        "category":       category,
        "resource":       resource,
        "issue":          issue,
        "recommendation": recommendation,
    })
    colour = SEVERITY_COLOUR.get(severity, "white")
    console.print(f"  [{colour}][{severity}][/{colour}] {resource} — {issue}")


def create_iam_client():
    """Create a boto3 IAM client using environment variables."""
    return boto3.client(
        "iam",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_DEFAULT_REGION", "ap-southeast-2"),
    )


# ─── Check 1: Wildcard permissions ───────────────────────────────────────────
def check_wildcard_permissions(iam):
    """
    Scan all customer-managed policies for Action:* or Resource:*
    These are the most dangerous misconfigurations — they grant unlimited access.
    Mapped to: CIS AWS Benchmark 1.16
    """
    console.print("\n[bold]Check 1 — Wildcard permissions[/bold]")

    paginator = iam.get_paginator("list_policies")

    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            policy_name = policy["PolicyName"]

            # Get the actual policy document
            version = iam.get_policy_version(
                PolicyArn=policy["Arn"],
                VersionId=policy["DefaultVersionId"],
            )
            document = version["PolicyVersion"]["Document"]
            statements = document.get("Statement", [])

            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue

                actions   = stmt.get("Action", [])
                resources = stmt.get("Resource", [])

                if isinstance(actions,   str): actions   = [actions]
                if isinstance(resources, str): resources = [resources]

                if "*" in actions:
                    add_finding(
                        "CRITICAL", "Wildcard Permission", policy_name,
                        "Policy allows Action:* (full access to all AWS services)",
                        "Replace '*' with only the specific actions this policy needs",
                    )

                if "*" in resources and "*" not in actions:
                    add_finding(
                        "HIGH", "Wildcard Resource", policy_name,
                        "Policy applies to Resource:* (all resources)",
                        "Scope the resource to specific ARNs where possible",
                    )


# ─── Check 2: Users with no MFA ──────────────────────────────────────────────
def check_mfa(iam):
    """
    Find IAM users who have console access but no MFA device.
    Without MFA a stolen password gives full account access.
    Mapped to: CIS AWS Benchmark 1.10
    """
    console.print("\n[bold]Check 2 — Users without MFA[/bold]")

    paginator = iam.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]

            # Check if user has console (password) access
            try:
                iam.get_login_profile(UserName=username)
                has_console = True
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    has_console = False
                else:
                    raise

            if not has_console:
                continue  # programmatic-only users don't need MFA

            # Check MFA devices
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

            if not mfa_devices:
                add_finding(
                    "CRITICAL", "Missing MFA", username,
                    "User has console access but no MFA device enabled",
                    "Enable MFA via IAM → Users → Security credentials → Assign MFA device",
                )


# ─── Check 3: Unused roles ────────────────────────────────────────────────────
def check_unused_roles(iam, days_threshold=90):
    """
    Find roles that haven't been used in over 90 days.
    Unused roles are dead attack surface — if compromised, they're invisible.
    Mapped to: CIS AWS Benchmark 1.16
    """
    console.print(f"\n[bold]Check 3 — Roles unused for {days_threshold}+ days[/bold]")

    paginator = iam.get_paginator("list_roles")
    now = datetime.now(timezone.utc)

    for page in paginator.paginate():
        for role in page["Roles"]:
            role_name = role["RoleName"]

            detail = iam.get_role(RoleName=role_name)["Role"]
            last_used = detail.get("RoleLastUsed", {}).get("LastUsedDate")

            if last_used is None:
                # Role has NEVER been used
                created = role["CreateDate"]
                age_days = (now - created).days
                if age_days > days_threshold:
                    add_finding(
                        "HIGH", "Unused Role", role_name,
                        f"Role has never been used (created {age_days} days ago)",
                        "Delete this role if it is no longer needed",
                    )
            else:
                days_since = (now - last_used).days
                if days_since > days_threshold:
                    add_finding(
                        "MEDIUM", "Unused Role", role_name,
                        f"Role has not been used for {days_since} days",
                        "Review and delete if no longer required",
                    )


# ─── Check 4: Inline policies ─────────────────────────────────────────────────
def check_inline_policies(iam):
    """
    Find users and roles with inline policies instead of managed policies.
    Inline policies are harder to audit because they are hidden inside the resource.
    Mapped to: CIS AWS Benchmark 1.16
    """
    console.print("\n[bold]Check 4 — Inline policies[/bold]")

    # Check users
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            inline = iam.list_user_policies(UserName=username)["PolicyNames"]
            if inline:
                add_finding(
                    "MEDIUM", "Inline Policy", username,
                    f"User has {len(inline)} inline policy/policies: {', '.join(inline)}",
                    "Convert inline policies to customer-managed policies for easier auditing",
                )

    # Check roles
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            role_name = role["RoleName"]
            inline = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
            if inline:
                add_finding(
                    "MEDIUM", "Inline Policy", role_name,
                    f"Role has {len(inline)} inline policy/policies: {', '.join(inline)}",
                    "Convert inline policies to customer-managed policies for easier auditing",
                )


# ─── Check 5: Old access keys ─────────────────────────────────────────────────
def check_old_access_keys(iam, days_threshold=90):
    """
    Find access keys older than 90 days that have not been rotated.
    Old keys are high risk — the longer a key exists, the more likely it has leaked.
    Mapped to: CIS AWS Benchmark 1.14
    """
    console.print(f"\n[bold]Check 5 — Access keys older than {days_threshold} days[/bold]")

    paginator = iam.get_paginator("list_users")
    now = datetime.now(timezone.utc)

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

            for key in keys:
                age_days = (now - key["CreateDate"]).days
                status   = key["Status"]

                if age_days > days_threshold and status == "Active":
                    add_finding(
                        "HIGH", "Old Access Key", username,
                        f"Active access key is {age_days} days old (threshold: {days_threshold})",
                        "Rotate this key: create a new one, update your apps, then delete the old one",
                    )

                if status == "Inactive" and age_days > days_threshold:
                    add_finding(
                        "MEDIUM", "Inactive Access Key", username,
                        f"Inactive access key is {age_days} days old — safe to delete",
                        "Delete inactive keys to reduce clutter and attack surface",
                    )


# ─── Summary report ───────────────────────────────────────────────────────────
def print_summary():
    """Print a final summary table of all findings grouped by severity."""
    console.print("\n")
    console.rule("[bold]Scan Complete — Summary[/bold]")

    if not findings:
        console.print("\n[bold green]✓ No issues found! Your IAM configuration looks clean.[/bold green]\n")
        return

    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    console.print(
        f"\n  [bold red]CRITICAL: {counts['CRITICAL']}[/bold red]   "
        f"[bold yellow]HIGH: {counts['HIGH']}[/bold yellow]   "
        f"[bold cyan]MEDIUM: {counts['MEDIUM']}[/bold cyan]\n"
    )

    # Full findings table
    table = Table(show_header=True, header_style="bold cyan", show_lines=True)
    table.add_column("Severity",       style="dim", width=10)
    table.add_column("Category",       width=20)
    table.add_column("Resource",       width=30)
    table.add_column("Issue",          width=45)
    table.add_column("Recommendation", width=45)

    for f in findings:
        colour = SEVERITY_COLOUR.get(f["severity"], "white")
        table.add_row(
            f"[{colour}]{f['severity']}[/{colour}]",
            f["category"],
            f["resource"],
            f["issue"],
            f["recommendation"],
        )

    console.print(table)

    # Save to JSON
    output_file = "iam_findings.json"
    with open(output_file, "w") as fp:
        json.dump(findings, fp, indent=2, default=str)
    console.print(f"\n[dim]Findings saved to {output_file}[/dim]\n")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    console.print(Panel(
        "[bold cyan]AWS IAM Analyser — Phase 2: Security Scanner[/bold cyan]\n"
        "[dim]Checks: Wildcard permissions · MFA · Unused roles · Inline policies · Old keys[/dim]",
        expand=False,
    ))

    iam = create_iam_client()

    check_wildcard_permissions(iam)
    check_mfa(iam)
    check_unused_roles(iam)
    check_inline_policies(iam)
    check_old_access_keys(iam)

    print_summary()


if __name__ == "__main__":
    main()
