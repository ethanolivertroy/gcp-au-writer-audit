# GCP Audit Writer Identity Tool

A Python tool for auditing IAM policies of Google Cloud logging sink writer identities. This tool validates permissions on sink destinations (Cloud Storage, BigQuery, Pub/Sub) to ensure compliance with the principle of least privilege.

## Features

- Validates logging sink writer identities
- Audits IAM policies for sink destinations:
  - Cloud Storage buckets
  - BigQuery datasets
  - Pub/Sub topics
- Identifies potential permission violations
- Supports NIST 800-53 compliance testing

## Prerequisites

### Google Cloud Setup

1. Install the [Google Cloud SDK](https://cloud.google.com/sdk/docs/install)
2. Set up authentication:
   - Create and download a service account key
   - Configure credentials:
     ```bash
     export GOOGLE_APPLICATION_CREDENTIALS="/path/to/your/service-account-key.json"
     ```

### Python Dependencies

Install required libraries:

```bash
pip install google-cloud-logging google-cloud-storage google-cloud-bigquery google-cloud-pubsub
```

## Usage

Run the tool with the following arguments:

```bash
python gcp-au-writer-audit.py --sink_name=SINK_NAME --project_id=PROJECT_ID
```

### Sample Output

The tool provides a detailed analysis:

```
# Writer Identity Information
Writer Identity: serviceAccount:service-123456789012@logging-sink.iam.gserviceaccount.com
Destination: bigquery.googleapis.com/projects/my-project/datasets/my_dataset

# IAM Policy Audit Results
IAM Policy Audit Findings:
- Role: roles/bigquery.dataOwner
  Members: ['serviceAccount:service-123456789012@logging-sink.iam.gserviceaccount.com']

# Summary
No excessive permissions found for the writer identity.
```

## Implementation Details

### Process Flow

1. **Writer Identity Retrieval**
   - Queries logging sink configuration
   - Extracts writer identity and destination

2. **IAM Policy Analysis**
   - Fetches resource-specific IAM policies
   - Analyzes assigned roles and permissions

3. **Permission Validation**
   - Checks against least-privilege requirements
   - Flags potential security issues

### Destination-Specific Requirements

| Destination Type | Required Role | Description |
|-----------------|---------------|-------------|
| Cloud Storage | roles/storage.objectCreator | Minimum permission for log writing |
| BigQuery | roles/bigquery.dataEditor | Allows dataset updates |
| Pub/Sub | roles/pubsub.publisher | Enables topic publishing |

### Might Need

```
pip3 install --user google-cloud-storage
pip3 install --user google-cloud-bigquery
pip3 install --user google-cloud-pubsub
pip3 install --user google-cloud-logging
```

## NIST 800-53 Compliance

This tool specifically tests compliance with the following NIST 800-53 controls:

### Primary Control: Least Privilege (AC-6)
- Validates that logging sink writer identities have only the minimum permissions required:
  - Cloud Storage: roles/storage.objectCreator
  - BigQuery: roles/bigquery.dataEditor
  - Pub/Sub: roles/pubsub.publisher
- Identifies and reports any excessive permissions

### Access Enforcement (AC-3)
- Verifies IAM policies properly enforce access control
- Ensures writer identities cannot perform unauthorized operations

### Protection of Audit Information (AU-9)
- Specifically tests AU-9(4) by validating access controls
- Confirms writer identities can only write logs, not modify or delete them

## Contributing

Contributions are welcome! Please ensure your changes align with the tool's security and compliance objectives.

## License

