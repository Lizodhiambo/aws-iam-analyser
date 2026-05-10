import boto3
import os
import json
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from botocore.exceptions import ClientError

load_dotenv()
console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# PRIVILEGE ESCALATION PATHS
# Each entry is a known combination of AWS permissions that allows a user
# to escalate to admin without ever being explicitly granted admin access.
# Source: Rhino Security Labs research on AWS IAM privilege escalation.
# ─────────────────────────────────────────────────────────────────────────────

ESCALATION_PATHS = [
    {
        "name": "Attach admin policy to self",
        "permissions": ["iam:AttachUserPolicy"],
        "description": "Can attach any policy (including AdministratorAccess) to their own user",
        "severity": "CRITICAL",
    },
    {
        "name": "Create and attach policy",
        "permissions": ["iam:CreatePolicy", "iam:AttachUserPolicy"],
        "description": "Can create a new admin policy and attach it to themselves",
        "severity": "CRITICAL",
    },
    {
        "name": "Create policy version",
        "permissions": ["iam:CreatePolicyVersion"],
        "description": "Can overwrite an existing policy with a new admin-level version",
        "severity": "CRITICAL",
    },
    {
        "name": "Set default policy version",
        "permissions": ["iam:SetDefaultPolicyVersion"],
        "description": "Can switch an existing policy to a previously created admin version",
        "severity": "CRITICAL",
    },
    {
        "name": "Create EC2 instance with admin role",
        "permissions": ["iam:PassRole", "ec2:RunInstances"],
        "description": "Can launch an EC2 instance with an admin IAM role attached and use it",
        "severity": "HIGH",
    },
    {
        "name": "Create Lambda with admin role",
        "permissions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "description": "Can create a Lambda function with an admin role and invoke it",
        "severity": "HIGH",
    },
    {
        "name": "Update Lambda function code",
        "permissions": ["lambda:UpdateFunctionCode"],
        "description": "Can modify existing Lambda code to exfiltrate credentials from its role",
        "severity": "HIGH",
    },
    {
        "name": "Add user to admin group",
        "permissions": ["iam:AddUserToGroup"],
        "description": "Can add themselves to a group that has admin permissions",
        "severity": "CRITICAL",
    },
    {
        "name": "Attach policy to group",
        "permissions": ["iam:AttachGroupPolicy"],
        "description": "Can attach admin policy to a group they belong to",
        "severity": "CRITICAL",
    },
    {
        "name": "Update assume role policy",
        "permissions": ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
        "description": "Can modify a role trust policy to allow themselves to assume an admin role",
        "severity": "CRITICAL",
    },
    {
        "name": "Create access key for other user",
        "permissions": ["iam:CreateAccessKey"],
        "description": "Can create access keys for other IAM users, including admins",
        "severity": "HIGH",
    },
    {
        "name": "Create login profile for other user",
        "permissions": ["iam:CreateLoginProfile"],
        "description": "Can set a console password for another user and log in as them",
        "severity": "HIGH",
    },
    {
        "name": "Update login profile for other user",
        "permissions": ["iam:UpdateLoginProfile"],
        "description": "Can reset the console password of another user, including admins",
        "severity": "CRITICAL",
    },
    {
        "name": "CloudFormation deploy with admin role",
        "permissions": ["iam:PassRole", "cloudformation:CreateStack"],
        "description": "Can deploy a CloudFormation stack using an admin role to run arbitrary actions",
        "severity": "HIGH",
    },
    {
        "name": "Glue endpoint with admin role",
        "permissions": ["iam:PassRole", "glue:CreateDevEndpoint"],
        "description": "Can create a Glue dev endpoint with an admin role to access credentials",
        "severity": "HIGH",
    },
]


def create_iam_client():
    return boto3.client(
        "iam",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_DEFAULT_REGION", "ap-southeast-2"),
    )


# ─── Collect all permissions for a user ──────────────────────────────────────

def get_user_permissions(iam, username):
    """
    Collect every permission a user has across:
    - Directly attached managed policies
    - Inline policies
    - Group memberships (and their policies)
    Returns a flat set of all allowed actions.
    """
    allowed = set()

    def extract_actions(document):
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                allowed.add(action.lower())

    # 1. Directly attached managed policies
    try:
        paginator = iam.get_paginator("list_attached_user_policies")
        for page in paginator.paginate(UserName=username):
            for policy in page["AttachedPolicies"]:
                version_id = iam.get_policy(
                    PolicyArn=policy["PolicyArn"]
                )["Policy"]["DefaultVersionId"]
                doc = iam.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=version_id,
                )["PolicyVersion"]["Document"]
                extract_actions(doc)
    except ClientError:
        pass

    # 2. Inline policies
    try:
        inline_names = iam.list_user_policies(UserName=username)["PolicyNames"]
        for name in inline_names:
            doc = iam.get_user_policy(
                UserName=username, PolicyName=name
            )["PolicyDocument"]
            extract_actions(doc)
    except ClientError:
        pass

    # 3. Group policies
    try:
        groups = iam.list_groups_for_user(UserName=username)["Groups"]
        for group in groups:
            gname = group["GroupName"]

            # Group managed policies
            paginator = iam.get_paginator("list_attached_group_policies")
            for page in paginator.paginate(GroupName=gname):
                for policy in page["AttachedPolicies"]:
                    version_id = iam.get_policy(
                        PolicyArn=policy["PolicyArn"]
                    )["Policy"]["DefaultVersionId"]
                    doc = iam.get_policy_version(
                        PolicyArn=policy["PolicyArn"],
                        VersionId=version_id,
                    )["PolicyVersion"]["Document"]
                    extract_actions(doc)

            # Group inline policies
            inline_names = iam.list_group_policies(GroupName=gname)["PolicyNames"]
            for name in inline_names:
                doc = iam.get_group_policy(
                    GroupName=gname, PolicyName=name
                )["PolicyDocument"]
                extract_actions(doc)
    except ClientError:
        pass

    return allowed


# ─── Check for escalation paths ──────────────────────────────────────────────

def check_escalation(permissions, identity):
    """
    Given a set of permissions, check each known escalation path.
    A path matches if the identity has ALL permissions in that path,
    OR if they have a wildcard (*) that covers those actions.
    """
    hits = []
    has_wildcard = "*" in permissions or "iam:*" in permissions

    for path in ESCALATION_PATHS:
        required = [p.lower() for p in path["permissions"]]

        if has_wildcard:
            hits.append(path)
            continue

        if all(p in permissions for p in required):
            hits.append(path)

    return hits


# ─── Scan all users ───────────────────────────────────────────────────────────

def scan_users(iam):
    console.print("\n[bold]Scanning IAM users for privilege escalation paths...[/bold]")
    findings = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            console.print(f"  [dim]Checking {username}...[/dim]")

            permissions = get_user_permissions(iam, username)
            hits = check_escalation(permissions, username)

            for hit in hits:
                colour = "bold red" if hit["severity"] == "CRITICAL" else "bold yellow"
                console.print(
                    f"    [{colour}][{hit['severity']}][/{colour}] "
                    f"{username} → {hit['name']}"
                )
                findings.append({
                    "type":        "User",
                    "identity":    username,
                    "path":        hit["name"],
                    "severity":    hit["severity"],
                    "permissions": hit["permissions"],
                    "description": hit["description"],
                })

    return findings


# ─── Summary ──────────────────────────────────────────────────────────────────

def print_summary(findings):
    console.print("\n")
    console.rule("[bold]Phase 4 — Privilege Escalation Scan Complete[/bold]")

    if not findings:
        console.print(
            "\n[bold green]✓ No privilege escalation paths found.[/bold green]\n"
        )
        return

    counts = {"CRITICAL": 0, "HIGH": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    console.print(
        f"\n  [bold red]CRITICAL: {counts['CRITICAL']}[/bold red]   "
        f"[bold yellow]HIGH: {counts['HIGH']}[/bold yellow]\n"
    )

    table = Table(show_header=True, header_style="bold cyan", show_lines=True)
    table.add_column("Severity",    width=10)
    table.add_column("Type",        width=8)
    table.add_column("Identity",    width=25)
    table.add_column("Escalation path", width=35)
    table.add_column("Description", width=50)

    for f in findings:
        colour = "bold red" if f["severity"] == "CRITICAL" else "bold yellow"
        table.add_row(
            f"[{colour}]{f['severity']}[/{colour}]",
            f["type"],
            f["identity"],
            f["path"],
            f["description"],
        )

    console.print(table)

    # Save findings
    out_file = "iam_escalation_findings.json"
    with open(out_file, "w") as fp:
        json.dump(findings, fp, indent=2, default=str)
    console.print(f"[dim]Saved to {out_file}[/dim]\n")

    # Explain what to do
    console.print("[bold]What to do with these findings:[/bold]")
    console.print("  1. Review each identity and confirm whether the permission is intentional")
    console.print("  2. Apply least privilege — remove permissions not needed for the job")
    console.print("  3. Use IAM Access Analyzer in AWS Console to get official recommendations")
    console.print("  4. Re-run this scanner after making changes to verify the fix\n")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    console.print(Panel(
        "[bold cyan]AWS IAM Analyser — Phase 4: Privilege Escalation Detector[/bold cyan]\n"
        "[dim]Checks 15 known escalation paths based on Rhino Security Labs research[/dim]",
        expand=False,
    ))

    iam = create_iam_client()
    findings = scan_users(iam)
    print_summary(findings)


if __name__ == "__main__":
    main()
