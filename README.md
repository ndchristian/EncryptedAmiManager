# ami_kms_fork_manager

CURRENTLY IN ALPHA.

Encrypted root volumes cannot be shared across AWS (Amazon Web Services) accounts. This utility allows the sharing of unencrypted AMIs (Amazon Machine Images) across accounts. The shared AMIs are copied,encrypted, and are tracked using DynamoDB to allow for governance.
