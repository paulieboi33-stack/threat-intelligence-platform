# 🔒 Threat Intelligence Report
Generated: 2026-04-26 12:02:56

## 📊 Executive Summary
- **Total Threats**: 20
- **Critical**: 3
- **High**: 9

## 🚨 Critical Threats

### CVE-2026-33945
- **Severity**: Critical
- **CVSS Score**: 9.9
- **Product**: Incus is a system container and virtual machine manager. Incus instances have an
- **Title**: Incus is a system container and virtual machine manager. Incus instances have an

**Description**:
Incus is a system container and virtual machine manager. Incus instances have an option to provide credentials to systemd in the guest. For containers, this is handled through a shared directory. Prio...

### CVE-2026-33701
- **Severity**: Critical
- **CVSS Score**: 9.8
- **Product**: OpenTelemetry Java Instrumentation provides OpenTelemetry auto-instrumentation a
- **Title**: OpenTelemetry Java Instrumentation provides OpenTelemetry auto-instrumentation a

**Description**:
OpenTelemetry Java Instrumentation provides OpenTelemetry auto-instrumentation and instrumentation libraries for Java. In versions prior to 2.26.1, the RMI instrumentation registered a custom endpoint...

### CVE-2026-33729
- **Severity**: Critical
- **CVSS Score**: 9.8
- **Product**: OpenFGA is a high-performance and flexible authorization/permission engine built
- **Title**: OpenFGA is a high-performance and flexible authorization/permission engine built

**Description**:
OpenFGA is a high-performance and flexible authorization/permission engine built for developers and inspired by Google Zanzibar. In versions prior to 1.13.1, under specific conditions, models using co...

### CVE-2026-27893
- **Severity**: High
- **CVSS Score**: 8.8
- **Product**: vLLM is an inference and serving engine for large language models (LLMs). Starti
- **Title**: vLLM is an inference and serving engine for large language models (LLMs). Starti

**Description**:
vLLM is an inference and serving engine for large language models (LLMs). Starting in version 0.10.1 and prior to version 0.18.0, two model implementation files hardcode `trust_remote_code=True` when ...

### CVE-2026-33898
- **Severity**: High
- **CVSS Score**: 8.8
- **Product**: Incus is a system container and virtual machine manager. Prior to version 6.23.0
- **Title**: Incus is a system container and virtual machine manager. Prior to version 6.23.0

**Description**:
Incus is a system container and virtual machine manager. Prior to version 6.23.0, the web server spawned by `incus webui` incorrectly validates the authentication token such that an invalid value will...
