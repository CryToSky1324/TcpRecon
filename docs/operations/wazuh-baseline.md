# Wazuh Clean Baseline

## Host

- OS: Ubuntu Server 24.04 LTS
- CPU: 2 cores
- RAM: 6 GB
- Swap: 8 GB
- Deployment: Wazuh all-in-one
- Purpose: TcpRecon SIEM integration lab

## Verified Components

- Wazuh manager: active
- Wazuh indexer: active
- Filebeat: active
- Wazuh dashboard: active
- Dashboard access: verified
- Indexer health: verified
- API port 55000: listening
- Agent ports 1514 and 1515: listening
- No OOM kills observed
- Clean configuration backup created

## Baseline Rule

No TcpRecon custom rules, ingestion configuration, dashboards, or integrations
are installed at this point.

This baseline is the rollback point before TcpRecon integration begins.
