# Security Policy

## Authorized use

TcpRecon is intended for systems and networks that you own or are explicitly authorized to assess. Do not use it for unauthorized scanning, service disruption, access attempts, or evasion of defensive controls.

Rate limiting exists to protect scanner and target resources. Documentation and examples must describe controlled or low-impact assessment, not stealth or detection avoidance.

## Reporting a vulnerability

Do not publish an exploitable vulnerability in a public issue before maintainers have had a reasonable opportunity to review it. Report:

- affected version or commit;
- operating environment;
- reproduction steps using an isolated lab;
- expected and observed behavior;
- security impact;
- suggested remediation, when known.

Do not include credentials, private target data, production logs, certificates, or persistent state databases.

## Sensitive repository content

The following must not be committed:

- Wazuh, OpenSearch, Slack, GHCR, or Kubernetes credentials;
- generated certificates and password archives;
- local bbolt databases;
- target lists containing private infrastructure;
- compiled binaries or diagnostic dumps containing sensitive banners.

## Supported versions

Until a stable release is tagged, security fixes apply to the current default branch. Release-specific support policy will be added after the event and state schemas reach version `1.0.0`.
