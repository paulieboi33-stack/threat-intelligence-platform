# 🔒 Threat Intelligence Report
Generated: 2026-05-01 18:02:47

## 📊 Executive Summary
- **Total Threats**: 20
- **Critical**: 1
- **High**: 7

## 🚨 Critical Threats

### CVE-2025-71279
- **Severity**: Critical
- **CVSS Score**: 9.8
- **Product**: XenForo before 2.3.7 contains a security issue affecting Passkeys that have been
- **Title**: XenForo before 2.3.7 contains a security issue affecting Passkeys that have been

**Description**:
XenForo before 2.3.7 contains a security issue affecting Passkeys that have been added to user accounts. An attacker may be able to compromise the security of Passkey-based authentication.

### CVE-2025-71278
- **Severity**: High
- **CVSS Score**: 8.8
- **Product**: XenForo before 2.3.5 allows OAuth2 client applications to request unauthorized s
- **Title**: XenForo before 2.3.5 allows OAuth2 client applications to request unauthorized s

**Description**:
XenForo before 2.3.5 allows OAuth2 client applications to request unauthorized scopes. This affects any customer using OAuth2 clients on any version of XenForo 2.3 prior to 2.3.5, potentially allowing...

### CVE-2025-71281
- **Severity**: High
- **CVSS Score**: 8.8
- **Product**: XenForo before 2.3.7 does not properly restrict methods callable from within tem
- **Title**: XenForo before 2.3.7 does not properly restrict methods callable from within tem

**Description**:
XenForo before 2.3.7 does not properly restrict methods callable from within templates. A loose prefix match was used instead of a stricter first-word match for methods accessible through callbacks an...

### CVE-2026-3775
- **Severity**: High
- **CVSS Score**: 7.8
- **Product**: The application's update service, when checking for updates, loads certain syste
- **Title**: The application's update service, when checking for updates, loads certain syste

**Description**:
The application's update service, when checking for updates, loads certain system libraries from a search path that includes directories writable by low‑privileged users and is not strictly restricted...

### CVE-2025-13855
- **Severity**: High
- **CVSS Score**: 7.6
- **Product**: IBM Storage Protect Server 8.2.0 IBM Storage Protect Plus Server is vulnerable t
- **Title**: IBM Storage Protect Server 8.2.0 IBM Storage Protect Plus Server is vulnerable t

**Description**:
IBM Storage Protect Server 8.2.0 IBM Storage Protect Plus Server is vulnerable to SQL injection. A remote attacker could send specially crafted SQL statements, which could allow the attacker to view, ...
