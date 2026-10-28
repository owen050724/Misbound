# Misbound

![status](https://img.shields.io/badge/status-early%20development-orange)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)

**Hierarchy-aware authorization testing for multi-tenant platforms.**

Misbound finds *resource–scope binding failures*: the permission check passes, but the object being operated on belongs to a different scope.

> **Status: early development.** The design below is the target. Nothing is functional yet.

---

## The problem

Most multi-tenant authorization bugs are not missing checks. They are checks applied to the wrong operand.

```java
// The permission check passes — the caller really does have write access to `projectCode`.
projectService.checkProjectAndAuth(loginUser, projectCode, WRITE);

// But the target is loaded by its own id. Nothing verifies that it
// actually belongs to `projectCode`.
TaskGroup taskGroup = taskGroupMapper.selectById(taskGroupId);
taskGroup.setStatus(newStatus);
taskGroupMapper.updateById(taskGroup);
```

The caller supplies a scope they legitimately control and an object id they do not. Authorization succeeds. The write lands in someone else's project.

The fix is the binding that was never there:

```java
if (taskGroup.getProjectCode() != projectCode) {
    throw new ServiceException(PROJECT_MISMATCH);
}
```

This is CWE-863 (Incorrect Authorization), not CWE-862 (Missing Authorization) — and the distinction is why the bug class survives both of the usual defenses.

## Why existing tools miss it

**Dynamic BOLA/IDOR scanners** assume a flat ownership model: user A owns object X, so test whether user B can read X. Under that model the request above is correct — it is authorized for the scope it names. The violation only becomes visible once you know that `taskGroup` sits *under* a project, which sits under a tenant, and that the request mixed levels.

**Static "missing auth check" rules** look for handlers with no authorization call. Here the call is present and correct. The defect is in what it was passed, which a presence check cannot express.

Misbound targets the gap between them: authorization that is present, passing, and bound to the wrong thing.

## How it works

1. **Scope specification.** A short YAML file declares the containment hierarchy and which request fields carry each level.

   ```yaml
   scopes:
     - name: tenant
     - name: project
       parent: tenant
       id_field: projectCode

   resources:
     - name: taskGroup
       scope: project
       id_field: taskGroupId
   ```

2. **Tenant provisioning.** Two mutually isolated tenants are created against a local instance of the target.

3. **Object graph construction.** An API trace (proxy capture or OpenAPI document) is replayed to learn which objects exist under which scope.

4. **Cross-scope substitution.** For each request, scope identifiers and object identifiers are swapped *across levels of the hierarchy* rather than merely between peer users — the operation that flat scanners never generate.

5. **Differential oracle.** Responses from the legitimate and substituted requests are compared to decide whether a boundary was actually crossed.

6. **Reporting.** SARIF and HTML output. Every finding carries the exact request that reproduces it.

An optional static pre-filter (tree-sitter) narrows which handlers get probed. It is **disabled by default**, requires no external AI service, and is fully deterministic — it reduces the candidate set, it does not decide findings.

## Validation plan

Misbound is evaluated against real vulnerabilities with published vendor patches, using the patched release as a control. A finding must appear in the vulnerable version and disappear in the fixed one.

| Target | CVE | Vulnerable | Fixed |
| --- | --- | --- | --- |
| Apache DolphinScheduler | [CVE-2026-57590](https://nvd.nist.gov/vuln/detail/CVE-2026-57590) | 3.4.2 | 3.4.3 |
| Apache DolphinScheduler | [CVE-2026-71897](https://nvd.nist.gov/vuln/detail/CVE-2026-71897) | 3.4.2 | 3.4.3 |
| Apache DolphinScheduler | [CVE-2026-66082](https://nvd.nist.gov/vuln/detail/CVE-2026-66082) | 3.4.2 | 3.4.3 |
| Apache DolphinScheduler | [CVE-2026-66084](https://nvd.nist.gov/vuln/detail/CVE-2026-66084) | 3.4.2 | 3.4.3 |
| ToolJet | [CVE-2026-73068](https://nvd.nist.gov/vuln/detail/CVE-2026-73068) | < v3.20.207-lts | v3.20.207-lts |

All five were found and reported by the author through coordinated disclosure, and are used here only because vendor advisories are already public.

## Roadmap

- [ ] Scope specification schema and parser
- [ ] Tenant provisioning drivers
- [ ] Object graph construction from API traces
- [ ] Cross-scope substitution engine
- [ ] Differential oracle
- [ ] SARIF / HTML reporting
- [ ] DolphinScheduler evaluation harness
- [ ] ToolJet evaluation harness
- [ ] Optional static candidate extractor

## Scope and intended use

Misbound is a defensive testing tool for systems you are authorized to test. All bundled evaluation targets run as **local Docker instances**. It performs state-changing requests by design and must never be pointed at production or at third-party deployments without written authorization.

## Prior work

Misbound builds on an existing body of authorization-testing tools and is deliberately scoped to what they do not cover.

- **Autorize**, **Auth Analyzer** — request replay under a second identity. Peer-user model.
- **[AuthProbe](https://github.com/jbarach2012/AuthProbe)**, **[GrantTrace](https://github.com/ysc070528/granttrace)**, **[AuthzTrace](https://pypi.org/project/authztrace/)**, **[PhaseAccess](https://pypi.org/project/phaseaccess/)** — OpenAPI-driven BOLA/IDOR scanners built on object ownership.
- **[Semgrep](https://semgrep.dev/)**, **Klocwork** (`SPRING.AUTHZ.MISSING`) — static detection of absent authorization checks.
- **AuthCheck** (Bauer et al., TAPAS 2019) — finite-state static analysis of authorization state.
- **OWASP API Security Top 10**, API1:2023 Broken Object Level Authorization.

None of these model containment hierarchies or generate cross-level identifier substitutions, which is the specific case Misbound addresses.

## License

Apache License 2.0. See [LICENSE](LICENSE).
