# 🔒 Threat Intelligence Report
Generated: 2026-05-17 06:00:06

## 📊 Executive Summary
- **Total Threats**: 20
- **Critical**: 0
- **High**: 6

## 🚨 Critical Threats

### CVE-2026-40262
- **Severity**: High
- **CVSS Score**: 8.7
- **Product**: Note Mark is an open-source note-taking application. In versions 0.19.1 and prio
- **Title**: Note Mark is an open-source note-taking application. In versions 0.19.1 and prio

**Description**:
Note Mark is an open-source note-taking application. In versions 0.19.1 and prior, the asset delivery handler serves uploaded files inline and relies on magic-byte detection for content type, which do...

### CVE-2026-22734
- **Severity**: High
- **CVSS Score**: 8.6
- **Product**: Cloud Foundry UUA is vulnerable to a bypass that allows an attacker to obtain a 
- **Title**: Cloud Foundry UUA is vulnerable to a bypass that allows an attacker to obtain a 

**Description**:
Cloud Foundry UUA is vulnerable to a bypass that allows an attacker to obtain a token for any user and gain access to UAA-protected systems. This vulnerability exists when SAML 2.0 bearer assertions a...

### CVE-2026-3605
- **Severity**: High
- **CVSS Score**: 8.1
- **Product**: An authenticated user with access to a kvv2 path through a policy containing a g
- **Title**: An authenticated user with access to a kvv2 path through a policy containing a g

**Description**:
An authenticated user with access to a kvv2 path through a policy containing a glob may be able to delete secrets they were not authorized to read or write, resulting in denial-of-service. This vulner...

### CVE-2026-4525
- **Severity**: High
- **CVSS Score**: 7.5
- **Product**: If a Vault auth mount is configured to pass through the "Authorization" header, 
- **Title**: If a Vault auth mount is configured to pass through the "Authorization" header, 

**Description**:
If a Vault auth mount is configured to pass through the "Authorization" header, and the "Authorization" header is used to authenticate to Vault, Vault forwarded the Vault token to the auth plugin back...

### CVE-2026-5807
- **Severity**: High
- **CVSS Score**: 7.5
- **Product**: Vault is vulnerable to a denial-of-service condition where an unauthenticated at
- **Title**: Vault is vulnerable to a denial-of-service condition where an unauthenticated at

**Description**:
Vault is vulnerable to a denial-of-service condition where an unauthenticated attacker can repeatedly initiate or cancel root token generation or rekey operations, occupying the single in-progress ope...
