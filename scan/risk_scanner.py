import re
from django.utils import timezone
from django.utils.timezone import is_naive, make_aware
from git import Repo
from .models import ScanResult

# ---------------------------------------------------------------------
# Risk Definitions: Each risk definition includes:
# - risk_type: A descriptive title.
# - pattern: A compiled regex pattern (if applicable).
# - file_filter: A lambda for filtering by file name (optional).
# - remediation: Guidance for fixing the issue.
# ---------------------------------------------------------------------
RISK_DEFINITIONS = [
    # Group 1: Authentication & Credentials Exposure
    {
        "risk_type": "SMTP Configuration Leak",
        "pattern": re.compile(r"(?i)(smtp.*(password|pass|secret).*=[\s'\"].+['\"])", re.MULTILINE),
        "remediation": "Remove hardcoded SMTP credentials and use environment variables."
    },
    {
        "risk_type": "Database Credentials Exposure",
        "pattern": re.compile(r"(?i)(db.*(password|user).*=[\s'\"].+['\"])", re.MULTILINE),
        "remediation": "Use secure methods for storing database credentials."
    },
    {
        "risk_type": "API Keys & Tokens Exposure",
        "pattern": re.compile(r"(?i)(api[_-]?key.*=[\s'\"].+['\"])", re.MULTILINE),
        "remediation": "Remove hardcoded API keys and use secure storage solutions."
    },
    {
        "risk_type": "OAuth Secrets Exposure",
        "pattern": re.compile(r"(?i)(oauth.*(client_id|client_secret).*=[\s'\"].+['\"])", re.MULTILINE),
        "remediation": "Do not commit OAuth client secrets; use secure storage."
    },
    {
        "risk_type": "Private SSH Key Exposure",
        "pattern": re.compile(r"-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----"),
        "remediation": "Remove private SSH keys from the repository and rotate compromised keys."
    },
    {
        "risk_type": "JWT Secret Exposure",
        "pattern": re.compile(r"(?i)(jwt.*secret.*=[\s'\"].+['\"])", re.MULTILINE),
        "remediation": "Store JWT secrets securely using environment variables."
    },
    {
        "risk_type": "Admin Credentials Exposure",
        "pattern": re.compile(r"(?i)(admin.*(password|user).*=[\s'\"].+['\"])", re.MULTILINE),
        "remediation": "Avoid hardcoding admin credentials; use secure authentication methods."
    },
    {
        "risk_type": "LDAP Configuration Exposure",
        "pattern": re.compile(r"(?i)(ldap.*(password|server).*=[\s'\"].+['\"])", re.MULTILINE),
        "remediation": "Secure LDAP credentials and configuration details appropriately."
    },
    {
        "risk_type": "VPN/Proxy Credentials Exposure",
        "pattern": re.compile(r"(?i)(vpn|proxy).*(password|user).*=[\s'\"].+['\"]", re.MULTILINE),
        "remediation": "Secure VPN and proxy credentials; do not commit them to version control."
    },
    {
        "risk_type": "Third-Party Service Login Credentials Exposure",
        "pattern": re.compile(r"(?i)(email|sms|cloud).*credentials.*=[\s'\"].+['\"]", re.MULTILINE),
        "remediation": "Remove hardcoded third-party service credentials and use secure storage."
    },
    # Group 2: User Data & Privacy Violations
    {
        "risk_type": "Usernames & Passwords Exposure",
        "pattern": re.compile(r"(?i)(username\s*=.*['\"].+['\"]|password\s*=.*['\"].+['\"])", re.MULTILINE),
        "remediation": "Ensure user credentials are hashed and never stored in plaintext."
    },
    {
        "risk_type": "Email Address Exposure",
        "pattern": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
        "remediation": "Avoid committing user email addresses in the repository."
    },
    {
        "risk_type": "Phone Number Exposure",
        "pattern": re.compile(r"\+?\d[\d\s\-]{7,}\d"),
        "remediation": "Remove or obfuscate phone numbers to protect user privacy."
    },
    {
        "risk_type": "Home Address Exposure",
        "pattern": re.compile(r"(?i)(\d{1,5}\s+\w+\s+(Street|St\.|Avenue|Ave\.|Road|Rd\.))"),
        "remediation": "Do not commit personal addresses; use placeholders or secure storage."
    },
    {
        "risk_type": "Social Security Number Exposure",
        "pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "remediation": "Remove SSNs from the repository; handle sensitive data with extreme care."
    },
    {
        "risk_type": "Credit Card Information Exposure",
        "pattern": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
        "remediation": "Do not store credit card information in source code."
    },
    {
        "risk_type": "Health Data Exposure",
        "pattern": re.compile(r"(?i)(patient|medical|health record)"),
        "remediation": "Handle health-related data in compliance with HIPAA and similar regulations."
    },
    {
        "risk_type": "Location Data Exposure",
        "pattern": re.compile(r"(?i)(latitude|longitude|geolocation)"),
        "remediation": "Avoid exposing precise location data in public repositories."
    },
    {
        "risk_type": "Private Messages Exposure",
        "pattern": re.compile(r"(?i)(private message|chat log|direct message)"),
        "remediation": "Remove private conversations or logs from the repository."
    },
    {
        "risk_type": "Biometric Data Exposure",
        "pattern": re.compile(r"(?i)(fingerprint|facial recognition|biometric)"),
        "remediation": "Do not store biometric data in your repository."
    },
    # Group 3: Code & Repository Security Risks
    {
        "risk_type": "Internal API Exposure",
        "pattern": re.compile(r"(?i)(internal_api|api/internal)"),
        "remediation": "Keep internal API endpoints secure and not publicly documented."
    },
    {
        "risk_type": "Debugging Logs Exposure",
        "pattern": re.compile(r"(?i)(DEBUG\s*:)"),
        "remediation": "Remove debugging logs from production code."
    },
    {
        "risk_type": "Sensitive Configuration File Exposure",
        "file_filter": lambda fp: any(x in fp.lower() for x in ['config.json', 'settings.py', '.env']),
        "pattern": None,
        "remediation": "Ensure configuration files with sensitive data are not committed."
    },
    {
        "risk_type": "Backup File Exposure",
        "file_filter": lambda fp: fp.lower().endswith(('.bak', '.tar.gz', '.zip')),
        "pattern": None,
        "remediation": "Remove backup files from the repository."
    },
    {
        "risk_type": "Hardcoded Encryption Key Exposure",
        "pattern": re.compile(r"(?i)(aes_key|rsa_private_key|encryption_key).*=[\s'\"].+['\"]", re.MULTILINE),
        "remediation": "Remove hardcoded encryption keys from the code."
    },
    {
        "risk_type": "Outdated Third-Party Dependencies",
        "file_filter": lambda fp: fp.lower() == 'requirements.txt',
        "pattern": re.compile(r"==\s*(\d+\.\d+\.\d+)"),
        "remediation": "Update third-party dependencies to secure versions."
    },
    # Group 4: Company & Business Risks
    {
        "risk_type": "Internal Business Strategies Exposure",
        "pattern": re.compile(r"(?i)(business plan|strategy)"),
        "remediation": "Do not commit internal business strategies to public repositories."
    },
    {
        "risk_type": "Private Contracts Exposure",
        "pattern": re.compile(r"(?i)(confidential agreement|NDA|contract)"),
        "remediation": "Remove any confidential contracts or agreements from the repository."
    },
    {
        "risk_type": "Unreleased Product Information Exposure",
        "pattern": re.compile(r"(?i)(release date|unreleased|coming soon)"),
        "remediation": "Keep unreleased product details private until public launch."
    },
    {
        "risk_type": "Sensitive Comments in Code",
        "pattern": re.compile(r"(?i)(todo:|fixme:).{0,100}"),
        "remediation": "Review code comments for sensitive information before committing."
    },
    {
        "risk_type": "Financial Reports Exposure",
        "pattern": re.compile(r"(?i)(revenue|profit|balance sheet|financial report)"),
        "remediation": "Do not store detailed financial reports in your repository."
    },
    {
        "risk_type": "HR & Employee Data Exposure",
        "pattern": re.compile(r"(?i)(salary|employee|resume|cv)"),
        "remediation": "Remove any HR or employee data from the repository."
    },
    {
        "risk_type": "Trade Secrets Exposure",
        "pattern": re.compile(r"(?i)(proprietary|trade secret|secret formula)"),
        "remediation": "Do not commit proprietary algorithms or formulas to the repository."
    },
    {
        "risk_type": "Unpublished Research Papers Exposure",
        "pattern": re.compile(r"(?i)(research paper|unpublished study)"),
        "remediation": "Keep unpublished research confidential."
    },
    {
        "risk_type": "Patented Code Exposure",
        "pattern": re.compile(r"(?i)(patent pending|patented)"),
        "remediation": "Avoid committing code containing unpublished patent details."
    },
    {
        "risk_type": "Vendor & Partner Information Exposure",
        "pattern": re.compile(r"(?i)(vendor|partner|supplier)"),
        "remediation": "Remove confidential vendor or partner information from the repository."
    },
    # Group 5: Operational & Compliance Risks
    {
        "risk_type": "Security Misconfigurations",
        "pattern": re.compile(r"(?i)(admin panel|dashboard)"),
        "remediation": "Secure admin panels and dashboards properly."
    },
    {
        "risk_type": "Lack of Access Controls",
        "pattern": re.compile(r"(?i)(access control|acl)"),
        "remediation": "Implement proper access controls for sensitive data."
    },
    {
        "risk_type": "PII Data Retention Violations",
        "pattern": re.compile(r"(?i)(PII|personally identifiable)"),
        "remediation": "Ensure PII is stored securely and in compliance with regulations."
    },
    {
        "risk_type": "Regulatory Compliance Violations",
        "pattern": re.compile(r"(?i)(GDPR|HIPAA|PCI DSS)"),
        "remediation": "Ensure compliance with applicable regulations."
    },
    {
        "risk_type": "Exposed Environment Variables",
        "pattern": re.compile(r"(?i)(env[_-]?var)"),
        "remediation": "Do not commit environment variable values; use secret management tools."
    },
    {
        "risk_type": "Accidental Deployment of Secrets",
        "pattern": re.compile(r"(?i)(\.env)"),
        "remediation": "Exclude secret files from deployments and use environment variables."
    },
    {
        "risk_type": "Leaked SSH Server Details",
        "pattern": re.compile(r"(?i)(ssh:\/\/|server_ip)"),
        "remediation": "Remove any SSH server details and secure your deployment configurations."
    },
    {
        "risk_type": "Weak or No Logging Policies",
        "pattern": re.compile(r"(?i)(logging\.info|logging\.debug)"),
        "remediation": "Review logging policies to avoid logging sensitive information."
    },
    {
        "risk_type": "Unprotected .git Directory Exposure",
        "file_filter": lambda fp: ".git" in fp.lower(),
        "pattern": None,
        "remediation": "Ensure .git directories are not exposed in deployed environments."
    }
    # Note: Risk 50 (Lack of Secret Scanning) is meta and not implemented.
]

def apply_risk_definitions(file_path, file_content):
    """
    Iterates through all risk definitions and returns a list of risk findings
    for the given file based on its path and content.
    """
    risks_found = []
    for definition in RISK_DEFINITIONS:
        # First, if a file_filter exists, check the file path.
        file_filter = definition.get("file_filter")
        if file_filter and file_filter(file_path):
            # If no content check is needed, record the risk.
            if not definition.get("pattern"):
                risks_found.append({
                    "risk_type": definition["risk_type"],
                    "snippet": file_content[:100],
                    "remediation": definition["remediation"]
                })
            else:
                match = definition["pattern"].search(file_content)
                if match:
                    snippet = match.group(0)
                    risks_found.append({
                        "risk_type": definition["risk_type"],
                        "snippet": snippet,
                        "remediation": definition["remediation"]
                    })
        # If no file filter is defined, simply check the file content.
        elif definition.get("pattern"):
            match = definition["pattern"].search(file_content)
            if match:
                snippet = match.group(0)
                risks_found.append({
                    "risk_type": definition["risk_type"],
                    "snippet": snippet,
                    "remediation": definition["remediation"]
                })
    return risks_found

def scan_repository(repo_path, scan_obj):
    """
    Scans only the HEAD commit of the active branch. For each file in the commit,
    it applies all defined risk checks and creates ScanResult entries for any risks found.
    """
    repo = Repo(repo_path)
    
    try:
        branch = repo.active_branch
        branch_name = branch.name
    except TypeError:
        # In detached HEAD state
        branch_name = "detached"
    
    commit = repo.head.commit
    if is_naive(commit.committed_datetime):
        commit_timestamp = make_aware(commit.committed_datetime)
    else:
        commit_timestamp = commit.committed_datetime

    # Traverse all files (blobs) in the commit tree.
    for blob in commit.tree.traverse():
        if blob.type == 'blob':
            try:
                file_content = blob.data_stream.read().decode('utf-8', errors='ignore')
            except Exception:
                continue
            risks = apply_risk_definitions(blob.path, file_content)
            for risk in risks:
                ScanResult.objects.create(
                    scan=scan_obj,
                    commit_hash=commit.hexsha,
                    branch=branch_name,
                    risk_type=risk.get('risk_type'),
                    file_path=blob.path,
                    snippet=risk.get('snippet'),
                    timestamp=commit_timestamp,
                    remediation=risk.get('remediation')
                )
