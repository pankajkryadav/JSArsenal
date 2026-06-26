# extractors.py
import re

PATTERNS = {
    "endpoints": r'["\'](?P<endpoints>/[^"\',? ]+)["\']',
    "params": r'[\?&](?P<params>[a-zA-Z0-9_.-]+=[^&"\']+)',
    "subdomains": r'https?://(?P<subdomains>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
    "emails": r'(?P<emails>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
    "secrets": r'(?:api_key|secret|password|token|auth_token)["\']?\s*[:=]\s*["\'](?P<secrets>[a-zA-Z0-9_.-]{16,})["\']',
    "cloud_urls": r'(?P<cloud_urls>https?://[a-zA-Z0-9.-]*(?:s3.amazonaws.com|storage.googleapis.com|blob.core.windows.net)[^"\']*)',
    "comments": r'(?P<comments>|//.*?$|/\*.*?\*/)',
    "tech_fingerprint": r'(?P<tech_fingerprint>react|jquery|angular|vue|express|nginx|apache|wordpress|drupal)',
    "js_api": r'(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["\'](?P<js_api>/[^"\']+)["\']',
    "jwt": r'(?P<jwt>eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)',
    "security_headers": r'(?P<security_headers><meta.*?Content-Security-Policy.*?>)',
    "integrations": r'(?P<integrations>google-analytics\.com|sentry\.io|stripe\.com|intercom\.io|hotjar\.com)',
    "js_vars": r'(?:var|let|const)\s+(?P<js_vars>[a-zA-Z0-9_]+\s*=\s*["\'][^"\']+["\'])',
    "form_endpoints": r'<form.*?action=["\'](?P<form_endpoints>[^"\']+)["\']',
    "version_info": r'(?P<version_info>v\d{1,2}\.\d{1,2}\.\d{1,3}|version|\b\d{1,2}\.\d{1,2}\.\d{1,3}\b|copyright|©)',
    "social_media": r'(?P<social_media>https?://(?:www\.)?(?:twitter\.com|linkedin\.com|facebook\.com|github\.com)/[a-zA-Z0-9_.-]+)',
    "graphql": r'(?P<graphql>/graphql|GraphQL)',
    "vuln_patterns": r'(?P<vuln_patterns>\.innerHTML|\.document\.write|dangerouslySetInnerHTML)',
    "postmessage": r'(?P<postmessage>window\.addEventListener\([\'"]message[\'"])'
}

# Define which patterns SecretFind should use
SECRETFIND_KEYS = ["endpoints", "secrets", "cloud_urls", "subdomains", "js_api", "emails", "params"]

def build_combined_regex(options, custom_pattern=""):
    """ -- MODIFIED -- Builds a regex based on user selections, with special handling for SecretFind. """
    selected_patterns = []

    # If SecretFind is chosen, it overrides other selections with a curated list.
    if options.get("SecretFind"):
        secretfind_patterns = [PATTERNS[key].replace(f"?P<{key}>", "") for key in SECRETFIND_KEYS]
        combined = "|".join(secretfind_patterns)
        # We use one named group for all combined findings.
        return re.compile(f"(?P<SecretFind>{combined})", re.IGNORECASE | re.MULTILINE)

    # Standard behavior if SecretFind is not selected
    for option, enabled in options.items():
        if enabled and option in PATTERNS:
            selected_patterns.append(PATTERNS[option])
    
    if options.get("custom_regex") and custom_pattern:
        selected_patterns.append(f"(?P<custom_regex>{custom_pattern})")

    if not selected_patterns:
        return None

    combined = "|".join(selected_patterns)
    return re.compile(combined, re.IGNORECASE | re.MULTILINE)

def run_extractors(content, combined_regex):
    """Runs the single combined regex and sorts the findings by category."""
    if not content or not combined_regex:
        return {}
    results = {group: set() for group in combined_regex.groupindex.keys()}
    for match in combined_regex.finditer(content):
        category = match.lastgroup
        if category:
            results[category].add(match.group(category))
    return {key: list(value) for key, value in results.items() if value}