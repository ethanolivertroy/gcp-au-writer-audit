#!/usr/bin/env python3
"""
GCP Audit Writer Identity Tool - Cloud Shell Version
Audits IAM policies of Google Cloud logging sink writer identities
"""

import sys
import argparse
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from google.api_core import exceptions
from google.cloud import storage, bigquery
from google.cloud import pubsub_v1
from google.cloud import logging_v2


@dataclass
class AuditFinding:
    """Represents an IAM policy audit finding."""
    role: str
    members: List[str]
    expected_role: Optional[str] = None

    def __str__(self) -> str:
        base = f"Role: {self.role}, Members: {self.members}"
        if self.expected_role:
            base += f"\nExpected Role: {self.expected_role}"
        return base


class DestinationType:
    """Supported destination types and their expected roles."""
    BIGQUERY = "bigquery.googleapis.com"
    STORAGE = "storage.googleapis.com"
    PUBSUB = "pubsub.googleapis.com"

    EXPECTED_ROLES = {
        BIGQUERY: "roles/bigquery.dataEditor",
        STORAGE: "roles/storage.objectCreator",
        PUBSUB: "roles/pubsub.publisher"
    }


def get_writer_identity(sink_name: str, project_id: str) -> Tuple[str, str]:
    """Retrieve the writer identity and destination for a specific logging sink."""
    try:
        client = logging_v2.Client(project=project_id)
        sink = client.sink(sink_name)
        sink.reload()
        return sink.writer_identity, sink.destination
    except exceptions.NotFound:
        raise ValueError(f"Sink '{sink_name}' not found in project '{project_id}'")


def get_storage_policy(bucket_name: str) -> Dict:
    """Retrieve IAM policy for a Cloud Storage bucket."""
    try:
        client = storage.Client()
        bucket = client.bucket(bucket_name)
        return bucket.get_iam_policy()
    except exceptions.NotFound:
        raise ValueError(f"Storage bucket '{bucket_name}' not found")


def get_bigquery_policy(dataset_id: str) -> Dict:
    """Retrieve IAM policy for a BigQuery dataset."""
    try:
        client = bigquery.Client()
        return client.get_iam_policy(dataset_id)
    except exceptions.NotFound:
        raise ValueError(f"BigQuery dataset '{dataset_id}' not found")


def get_pubsub_policy(topic_name: str, project_id: str) -> Dict:
    """Retrieve IAM policy for a Pub/Sub topic."""
    try:
        client = pubsub_v1.PublisherClient()
        topic_path = client.topic_path(project_id, topic_name)
        request = {"resource": topic_path}
        return client.get_iam_policy(request=request)
    except exceptions.NotFound:
        raise ValueError(f"Pub/Sub topic '{topic_name}' not found")


def audit_policy(
    policy: Dict,
    writer_identity: str,
    destination_type: str
) -> List[AuditFinding]:
    """Audit the IAM policy for excessive permissions."""
    findings = []
    bindings = getattr(policy, 'bindings', policy)
    expected_role = DestinationType.EXPECTED_ROLES.get(destination_type)

    for role, members in bindings.items():
        if writer_identity in members:
            finding = AuditFinding(
                role=role,
                members=members,
                expected_role=expected_role
            )
            findings.append(finding)

    return findings


def get_destination_info(destination: str) -> Tuple[str, str, str]:
    """Parse destination URL into type, name, and project."""
    parts = destination.split('/')
    dest_type = parts[0]
    
    if len(parts) < 2:
        raise ValueError(f"Invalid destination format: {destination}")
        
    resource_name = parts[-1]
    project_id = parts[2] if len(parts) > 2 else None
    
    return dest_type, resource_name, project_id


def main():
    parser = argparse.ArgumentParser(
        description="Audit IAM policies of a logging sink's writer identity."
    )
    parser.add_argument("--sink_name", required=True, help="Name of the logging sink")
    parser.add_argument("--project_id", required=True, help="GCP project ID")
    args = parser.parse_args()

    try:
        # Get writer identity and destination
        writer_identity, destination = get_writer_identity(args.sink_name, args.project_id)
        print(f"Writer Identity: {writer_identity}")
        print(f"Destination: {destination}")

        dest_type, resource_name, dest_project = get_destination_info(destination)
        project_id = dest_project or args.project_id

        # Get and audit policy based on destination type
        if dest_type.startswith(DestinationType.BIGQUERY):
            policy = get_bigquery_policy(resource_name)
        elif dest_type.startswith(DestinationType.STORAGE):
            policy = get_storage_policy(resource_name)
        elif dest_type.startswith(DestinationType.PUBSUB):
            policy = get_pubsub_policy(resource_name, project_id)
        else:
            sys.exit(f"Error: Unsupported destination type: {dest_type}")

        findings = audit_policy(policy, writer_identity, dest_type)

        # Report findings
        if findings:
            print("\nIAM Policy Audit Findings:")
            for finding in findings:
                print(f"- {finding}")
        else:
            print("\nNo excessive permissions found for the writer identity")

    except ValueError as e:
        sys.exit(f"Error: {str(e)}")
    except Exception as e:
        sys.exit(f"Unexpected error: {str(e)}")


if __name__ == "__main__":
    main()