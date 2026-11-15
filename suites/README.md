# Suites

One folder per surface and tier, matching the roadmap.

| Folder | Covers |
|---|---|
| `datacenter/t1` | Content, child content, descendants, attachments, labels, versions, body conversion, spaces, search, users, server information, long tasks |
| `datacenter/t2` | Content and space properties, restrictions, webhooks, space permissions, groups, label lists, watches |
| `datacenter/t3` | Administration operations |
| `cloud/v1` | Cloud v1 |
| `cloud/v2` | Cloud v2, by tier |
| `auth` | Basic auth, personal access tokens, OAuth 2.0 with PKCE and refresh |
| `migration` | Aerie-to-aerie migration through the Data Center surface |

Each operation gets a success case, a not-allowed case, a not-found case and, where it applies, paging and `expand` cases.
