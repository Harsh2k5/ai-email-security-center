# AI Spam Detection System

This repository contains a modular, multi-layered email spam detection pipeline. It integrates advanced content analysis using DistilBERT with comprehensive email authentication checks (SPF, DKIM, DMARC) and real-time threat intelligence sources (VirusTotal, Google Safe Browsing, AbuseIPDB, URLhaus) to identify and respond to malicious emails within enterprise environments.

The system consists of multiple components:

- **Preprocessing**: Text cleansing and header analysis (SPF, DKIM, DMARC).
- **Content Analysis**: Email body tokenization, cleaning, and URL extraction.
- **Email Authentication**: Headers validated using SPF, DKIM, and DMARC protocols.
- **Threat Intelligence**: URLs and attachments checked via VirusTotal, Google Safe Browsing, AbuseIPDB, and URLhaus.
- **Machine Learning Model**: DistilBERT-based classifier trained on curated datasets.
- **Aggregation & Decision**: Combines results to assess spam likelihood, supporting SOC alerting and API deployment.

## Features

- Text and Header Preprocessing
- DistilBERT-based Email Classification
- SPF, DKIM, DMARC Validation
- External Threat Intelligence API Integration
- Flask REST API for deployment
- Security Operations Center (SOC) Support
- Modular and extensible pipeline
