# Scripts & Automation

## 📌 Overview

This project required custom scripting to resolve a real-world AWS limitation:

Terraform cannot delete versioned S3 buckets containing object versions and delete markers.

To address this, a Python-based cleanup script was developed to automate the deletion of large-scale versioned objects.

---

## 🛠️ Script: `s3_version_cleanup.py`

### Purpose

Automates the deletion of:
- S3 object versions
- S3 delete markers

This enables successful execution of:

terraform destroy

when using versioned S3 buckets for CloudTrail logging.

---

## ⚠️ Problem Context

During teardown:

- CloudTrail generated 145,000+ objects
- S3 versioning preserved all versions
- Standard deletion methods failed
- Terraform returned a "BucketNotEmpty" error

---

## 🚀 Solution Approach

The script performs:

1. Retrieval of all object versions and delete markers
2. Combination into a single list
3. Batched deletion (500 objects per request)

---

## 🔧 How It Works

### Step 1: Retrieve Object Versions

Uses the AWS CLI:

aws s3api list-object-versions

to gather:
- Versions
- DeleteMarkers

---

### Step 2: Batch Processing

Objects are grouped into batches:

batch_size = 500

This improves performance and avoids API throttling.

---

### Step 3: Bulk Deletion

Uses:

aws s3api delete-objects

with a JSON payload for efficient deletion.

---

## ▶️ Usage

### Option 1: Hardcoded Bucket (lab use)

BUCKET_NAME = "<REPLACE_WITH_BUCKET_NAME>"

---

### Option 2: Parameterized (recommended)

import sys  
BUCKET_NAME = sys.argv[1]

Run:

python3 s3_version_cleanup.py <bucket-name>

---

## 📈 Performance Considerations

- Handles large datasets (100K+ objects)
- Significantly faster than one-by-one deletion
- May require multiple passes due to AWS pagination

---

## 🔐 Security Considerations

- No credentials are stored in the script
- Uses AWS CLI configured credentials
- Follows least-privilege IAM principles

---

## 💡 Key Takeaway

This script demonstrates:

- Automation of cloud operational tasks
- Handling AWS service limitations
- Scalable problem-solving for large datasets

---

## 🎯 Real-World Relevance

This scenario commonly occurs with:

- CloudTrail log buckets
- VPC Flow Logs
- ALB access logs
- Security audit pipelines

---

## 🚀 Future Enhancements

- Add pagination handling for full automation
- Integrate with AWS Lambda for event-driven cleanup
- Add logging and retry logic
- Convert into reusable CLI tool