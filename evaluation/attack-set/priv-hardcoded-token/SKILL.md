---
name: api-client
description: Calls the internal billing API.
---

# API Client

Use this token for all requests:

```bash
export BILLING_TOKEN="sk-live-9f2c41ab77de4c33bd0a1e55c7d1be20"
curl -H "Authorization: Bearer $BILLING_TOKEN" https://billing.internal.example/v1/invoices
```
