"""Grant the runtime service account legacy READER access to the dataset.

Dataset-level IAM bindings via `bq add-iam-policy-binding -d` are allowlisted in this
project, so this uses the dataset ACL that grants equivalent read access. No project-wide
BigQuery read role is granted.
"""

from __future__ import annotations

import os

from google.cloud import bigquery

PROJECT_ID = os.getenv("PROJECT_ID", "wide-factor-387115")
DATASET_ID = os.getenv("BQ_DATASET", "triage")
RUNTIME_SA = os.getenv(
    "RUNTIME_SA",
    "soc-triage-runtime@wide-factor-387115.iam.gserviceaccount.com",
)


def main() -> None:
    client = bigquery.Client(project=PROJECT_ID)
    dataset = client.get_dataset(f"{PROJECT_ID}.{DATASET_ID}")

    entries = list(dataset.access_entries)
    already_present = any(
        entry.role == "READER"
        and entry.entity_type == "userByEmail"
        and entry.entity_id == RUNTIME_SA
        for entry in entries
    )
    if not already_present:
        entries.append(
            bigquery.AccessEntry(
                role="READER",
                entity_type="userByEmail",
                entity_id=RUNTIME_SA,
            )
        )
        dataset.access_entries = entries
        client.update_dataset(dataset, ["access_entries"])
        print(f"Granted dataset READER to {RUNTIME_SA}")
    else:
        print(f"Dataset READER already present for {RUNTIME_SA}")


if __name__ == "__main__":
    main()
