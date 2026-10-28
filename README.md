# Misbound
Hierarchy-aware authorization tester for multi-tenant platforms. Finds resource-scope binding failures (CWE-863) that flat BOLA/IDOR scanners miss: the permission check passes, but the target object belongs to another scope. Every finding ships with a reproducible request.
