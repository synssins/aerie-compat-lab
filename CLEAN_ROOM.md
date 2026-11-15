# Clean-room policy: compatibility lab

This repository proves aerie compatible by running vendors' published clients against the aerie container image. It tests a black box: it needs no access to aerie's source.

## The three repositories

| Repository | Role |
|---|---|
| `aerie-spec` | Spec room: written specs, contracts, the provenance ledger |
| `aerie` | Build room: implementation from tagged contract releases only |
| `aerie-compat-lab` (this one) | Lab: vendors' published clients run against the aerie image |

## May be used

- Clients generated from vendors' published OpenAPI files, generated at run time from files pinned by address and SHA-256 in `clients/specs.csv`. Generated code is not committed.
- Community client libraries under licenses that allow this use, pinned by version.
- The aerie container image and aerie's released contracts.
- Vendors' public documentation, to write scenarios.

## Never allowed in any repository

- Leaked or proprietary source code
- Decompiled or disassembled binaries
- Confidential information from a current or former employer
- Copied UI assets, screenshots or trademarks of another product
- Customer code or customer data: customers run their own tests and send back results only

## What leaves the lab

Only black-box results: the request sent, the response aerie gave, and our diff of them. Build bugs are filed in `aerie`; contract bugs in `aerie-spec`. Vendor documentation and vendor response samples never leave this repository.

## Review

Every change lands by pull request with one approving human review.
