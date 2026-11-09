# Agent Security Governance

This context describes how Agents, their extensions, and runtime actions are represented as security evidence across managed devices.

## Inventory and risk language

**Asset provenance**:
The known origin and acquisition channel of an Agent, MCP server, Skill, Hook, or dependency. Provenance says where an asset came from; it does not say whether its content is safe.
_Avoid_: trusted because installed, malicious because unregistered

**Plugin cache**:
An endpoint-local copy of plugin metadata, Skills, MCP definitions, or dependencies made available by an Agent's plugin manager. Presence in the cache does not prove the plugin was explicitly installed or activated by the user.
_Avoid_: user-installed asset, active MCP server

**Logical asset**:
The product-level identity of one Agent, Skill, MCP server, Hook, or dependency
across hosts and filesystem copies. It is identified by product, kind, and
canonical name; a logical asset may have multiple physical instances.
_Avoid_: one path, one asset

**Physical instance**:
One host/carrier/path copy of a logical asset. An instance records where the
asset was observed and whether that copy is cached, installed, enabled, active,
disabled, or removed.
_Avoid_: logical asset, content identity

**Asset carrier**:
The evidence-backed location category of an instance, such as marketplace
cache, product builtin, user installed, project local, vendor dependency, or
synthetic. Carrier describes origin and scope; it does not establish safety.
_Avoid_: provenance as trust

**Asset state**:
The lifecycle state inferred from evidence for one physical instance. A path
that was merely discovered cannot be reported as installed or active without a
product reference, enablement evidence, or runtime use evidence.
_Avoid_: scanner verdict, risk assessment

**Content hash**:
The digest of normalized asset content used to recognize identical copies and
detect drift. A content hash is separate from logical identity and instance
identity.
_Avoid_: path hash as logical identity

**Asset release**:
A versioned, verifiable publication of a logical asset. A release binds
version, publisher, namespace, source URI, signature, and normalized content
hash. Two versions or two publishers are different releases even when their
display names match.
_Avoid_: logical asset, physical instance

**Dependency closure**:
The set of packages, executables, images, configuration, environment inputs,
APIs, and nested assets required to install or run an instance. Unresolved or
dynamic dependencies remain explicitly unknown and do not count as verified
supply-chain evidence.
_Avoid_: direct manifest only

**Installation state**:
The state of whether a physical instance is cached, installed, or removed.
Installation state is independent from whether the instance is enabled or
currently running.
_Avoid_: one lifecycle status for all dimensions

**Activation state**:
The product configuration state of an instance: enabled or disabled. It is
evidence about product configuration, not proof that the instance was loaded.
_Avoid_: active runtime

**Runtime state**:
The observed execution state of an instance: idle, active, or terminated.
Runtime state requires Hook, process, load, or last-used evidence.
_Avoid_: installed means active

**Admission enforcement**:
The side-effecting layer that controls the actual install or enable write after
the policy engine has returned allow, ask, or block. It owns permissions,
idempotency, staging, commit, compensation, and reconciliation.
_Avoid_: pure policy decision

**Commit verification**:
The post-write check that re-hashes the release, confirms the product reference
and feedback, and only then advances the instance state. A successful file
write alone is not a commit.
_Avoid_: write success as enabled evidence

**Finding**:
A detector observation tied to evidence and a rule. A finding can be a false positive and is not, by itself, a final verdict about an asset or person.
_Avoid_: confirmed threat

**Scanner verdict**:
The static scanner's operational result (`clean`, `alert`, or `block`) based on configured rule actions. It describes policy handling for the current scan, not a confirmed malware judgement.
_Avoid_: threat verdict, maliciousness

**Risk assessment**:
The current evidence-based status of an asset or action, including its confidence and evidence sources. Static rules, publisher verification, runtime observations, ThreatBook reputation, and analyst review remain distinguishable inputs.
_Avoid_: scanner verdict as truth

**Confirmed malicious**:
A finding adjudicated by an authorized analyst or a high-confidence authoritative source with sufficient context. An unregistered asset, a hash change, or a static rule hit alone does not meet this definition.
_Avoid_: suspicious, high-risk candidate

**Runtime evidence**:
An observation of an Agent tool decision, process, file operation, or network connection, bound to a host and session where possible.
_Avoid_: intent evidence, policy result

**Enforcement evidence**:
Evidence that a control sat on the execution path and the product honored an allow, ask, or deny decision. A side-channel alert or a policy page entry is not enforcement evidence.
_Avoid_: detected, audited

**Device heartbeat**:
A time-stamped report from an enrolled endpoint indicating that its collector is alive and describing its local queue and upload state.
_Avoid_: any-event last seen

**Admission gate**:
The policy-controlled checkpoint that runs before an asset is installed,
enabled, or loaded. It evaluates identity, content integrity, carrier, risk,
scope, approval, and product feedback; a scanner finding alone is not an
admission commit.
_Avoid_: scan result as installation proof

**Runtime coverage**:
The strongest product-specific control level proven for a runtime event:
inventory, observe, ask, or deny. Coverage is versioned and platform-specific;
an observed event does not prove the product enforced a decision.
_Avoid_: discovered adapter as blocking coverage

**Enforcement evidence**:
A product or operating-system record showing that an allow, ask, or deny
decision was on the execution path and took effect. This is counted separately
from detection and observation evidence.
_Avoid_: policy page entry, side-channel alert
