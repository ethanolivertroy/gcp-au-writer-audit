import os
import argparse
from google.cloud import storage, bigquery, pubsub_v1, iam

def get_writer_identity(sink_name, project_id):
    """Retrieve the writer identity for a specific logging sink."""
    from google.cloud import logging

    client = logging.Client(project=project_id)
    sink = client.sink(sink_name)
    sink.reload()

    return sink.writer_identity, sink.destination

def get_storage_policy(bucket_name):
    """Retrieve IAM policy for a Cloud Storage bucket."""
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    policy = bucket.get_iam_policy()
    return policy

def get_bigquery_policy(dataset_id):
    """Retrieve IAM policy for a BigQuery dataset."""
    client = bigquery.Client()
    policy = client.get_iam_policy(dataset_id)
    return policy

def get_pubsub_policy(topic_name):
    """Retrieve IAM policy for a Pub/Sub topic."""
    client = pubsub_v1.PublisherClient()
    topic_path = client.topic_path(project_id, topic_name)
    policy = client.get_iam_policy(request={"resource": topic_path})
    return policy

def audit_policy(policy, writer_identity):
    """Audit the IAM policy for excessive permissions."""
    findings = []
    for role, members in policy.items():
        if writer_identity in members:
            findings.append((role, members))
    return findings

def main():
    parser = argparse.ArgumentParser(description="Audit IAM policies of a logging sink's writer identity.")
    parser.add_argument("--sink_name", required=True, help="The name of the logging sink.")
    parser.add_argument("--project_id", required=True, help="The GCP project ID.")

    args = parser.parse_args()

    # Authenticate using the Google Cloud SDK authentication
    if not os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        print("Please set the GOOGLE_APPLICATION_CREDENTIALS environment variable to your service account key.")
        return

    # Get writer identity and destination
    writer_identity, destination = get_writer_identity(args.sink_name, args.project_id)
    print(f"Writer Identity: {writer_identity}")
    print(f"Destination: {destination}")

    # Check IAM policies based on destination type
    if destination.startswith("bigquery.googleapis.com"):  # BigQuery
        dataset_id = destination.split("/")[-1]
        policy = get_bigquery_policy(dataset_id)
        findings = audit_policy(policy.bindings, writer_identity)
    elif destination.startswith("storage.googleapis.com"):  # Cloud Storage
        bucket_name = destination.split("/")[-1]
        policy = get_storage_policy(bucket_name)
        findings = audit_policy(policy, writer_identity)
    elif destination.startswith("pubsub.googleapis.com"):  # Pub/Sub
        topic_name = destination.split("/")[-1]
        policy = get_pubsub_policy(topic_name)
        findings = audit_policy(policy.bindings, writer_identity)
    else:
        print("Unsupported destination type.")
        return

    # Report findings
    if findings:
        print("\nIAM Policy Audit Findings:")
        for role, members in findings:
            print(f"- Role: {role}, Members: {members}")
    else:
        print("\nNo excessive permissions found for the writer identity.")

if __name__ == "__main__":
    main()
