# API Reference — aumai-sandbox

All public symbols are importable directly from `aumai_sandbox`:

```python
from aumai_sandbox import (
    CapabilityDeclaration,
    CapabilityParser,
    CapabilityParseError,
    EgressFilter,
    FilesystemConfig,
    FilesystemMode,
    FilesystemPolicy,
    NetworkEgressRule,
    ResourceLimits,
    ResourceMonitor,
    SandboxError,
    SandboxManager,
    SandboxResult,
    SandboxStatus,
    SandboxTier,
    check_egress,
    check_limits,
    validate_path_access,
)
```

---

## Models (`aumai_sandbox.models`)

### `SandboxTier`

```python
class SandboxTier(str, enum.Enum):
    seccomp     = "seccomp"
    gvisor      = "gvisor"
    firecracker = "firecracker"
```

Isolation tier for a sandbox. Maps to real Linux kernel technologies.

| Value | Description |
|---|---|
| `seccomp` | Subprocess isolation with filtered environment. Portable; works on all platforms. |
| `gvisor` | Invokes `runsc run` on Linux with gVisor installed. Genuine kernel isolation. |
| `firecracker` | Firecracker microVM on Linux. Highest isolation; wired in a future backend. |

On non-Linux hosts, `SandboxManager` falls back to subprocess isolation regardless of
the tier value, and issues a `UserWarning`.

---

### `NetworkEgressRule`

```python
class NetworkEgressRule(BaseModel):
    domain:             str       # FQDN or wildcard prefix
    ports:              list[int] # default []
    rate_limit_per_min: int       # default 60, ge=1
```

Single allow-listed egress destination.

**Fields:**

| Field | Type | Default | Constraint | Description |
|---|---|---|---|---|
| `domain` | `str` | required | not blank | FQDN or `*.` wildcard prefix, e.g. `*.example.com` |
| `ports` | `list[int]` | `[]` | each 1–65535 | Allowed TCP/UDP ports; empty list means all ports |
| `rate_limit_per_min` | `int` | `60` | ge=1 | Max outbound requests per minute to this domain |

**Validators:**
- `domain` must not be blank (strips whitespace, raises `ValueError` if empty).
- Each element of `ports` must be in range 1–65535.

**Example:**

```python
from aumai_sandbox import NetworkEgressRule

# Allow HTTPS to OpenAI with a 30 req/min cap
rule = NetworkEgressRule(domain="api.openai.com", ports=[443], rate_limit_per_min=30)

# Allow any port to an internal registry
rule2 = NetworkEgressRule(domain="internal.registry.company.com")

# Wildcard subdomain
rule3 = NetworkEgressRule(domain="*.anthropic.com", ports=[443])
```

---

### `FilesystemMode`

```python
class FilesystemMode(str, enum.Enum):
    read_only  = "read_only"
    read_write = "read_write"
    none       = "none"
```

| Value | Reads | Writes |
|---|---|---|
| `read_only` | All paths | None |
| `read_write` | All paths | `writable_paths` only (or all if `writable_paths` is empty) |
| `none` | None | None |

---

### `FilesystemConfig`

```python
class FilesystemConfig(BaseModel):
    mode:           FilesystemMode  # default read_only
    writable_paths: list[str]       # default []
```

Filesystem isolation policy for a sandbox.

**Fields:**

| Field | Type | Default | Description |
|---|---|---|---|
| `mode` | `FilesystemMode` | `read_only` | Access level granted to the sandbox |
| `writable_paths` | `list[str]` | `[]` | Absolute paths writable by the sandbox (mode=`read_write` only) |

**Validators:**
- `writable_paths` must be empty when `mode` is not `read_write`. Raises `ValueError` otherwise.

**Examples:**

```python
from aumai_sandbox import FilesystemConfig, FilesystemMode

# Read-only (default)
config = FilesystemConfig()

# No filesystem access at all
config = FilesystemConfig(mode=FilesystemMode.none)

# Read-write with specific writable directories
config = FilesystemConfig(
    mode=FilesystemMode.read_write,
    writable_paths=["/tmp/agent_work", "/var/agent/output"],
)
```

---

### `ResourceLimits`

```python
class ResourceLimits(BaseModel):
    max_memory_mb:   int   # default 512, ge=1
    max_cpu_seconds: float # default 30.0, gt=0
    max_cost_usd:    float # default 0.10, gt=0
    max_tokens:      int   # default 100_000, ge=1
```

Hard resource caps enforced by `ResourceMonitor`.

**Fields:**

| Field | Type | Default | Constraint | Description |
|---|---|---|---|---|
| `max_memory_mb` | `int` | `512` | ge=1 | Maximum resident memory in MiB |
| `max_cpu_seconds` | `float` | `30.0` | gt=0 | Maximum total CPU time in seconds |
| `max_cost_usd` | `float` | `0.10` | gt=0 | Maximum USD spend (LLM API calls etc.) |
| `max_tokens` | `int` | `100_000` | ge=1 | Maximum token budget across all LLM calls |

**Example:**

```python
from aumai_sandbox import ResourceLimits

limits = ResourceLimits(
    max_memory_mb=256,
    max_cpu_seconds=15.0,
    max_cost_usd=0.05,
    max_tokens=50_000,
)
```

---

### `CapabilityDeclaration`

```python
class CapabilityDeclaration(BaseModel):
    sandbox_tier:          SandboxTier           # default seccomp
    network_egress_rules:  list[NetworkEgressRule] # default []
    filesystem_config:     FilesystemConfig       # default FilesystemConfig()
    resource_limits:       ResourceLimits         # default ResourceLimits()
    permissions:           list[str]              # default []
    env_allowlist:         list[str] | None       # default None
```

Full capability specification governing a sandboxed agent.

**Fields:**

| Field | Type | Default | Description |
|---|---|---|---|
| `sandbox_tier` | `SandboxTier` | `seccomp` | Isolation backend |
| `network_egress_rules` | `list[NetworkEgressRule]` | `[]` | Outbound network allowlist; empty = deny all |
| `filesystem_config` | `FilesystemConfig` | `FilesystemConfig()` | Filesystem access policy |
| `resource_limits` | `ResourceLimits` | `ResourceLimits()` | Hard resource caps |
| `permissions` | `list[str]` | `[]` | Named capability tokens |
| `env_allowlist` | `list[str] \| None` | `None` | When set with `read_env`, only these vars pass through |

**Permission tokens:**

| Token | Effect |
|---|---|
| `read_env` | Agent subprocess inherits filtered environment variables |
| `spawn_subprocess` | (Reserved for future enforcement) |

**Example:**

```python
from aumai_sandbox import (
    CapabilityDeclaration, FilesystemConfig, FilesystemMode,
    NetworkEgressRule, ResourceLimits, SandboxTier,
)

capability = CapabilityDeclaration(
    sandbox_tier=SandboxTier.gvisor,
    resource_limits=ResourceLimits(max_memory_mb=256, max_cpu_seconds=10.0),
    filesystem_config=FilesystemConfig(
        mode=FilesystemMode.read_write,
        writable_paths=["/tmp/work"],
    ),
    network_egress_rules=[
        NetworkEgressRule(domain="api.openai.com", ports=[443]),
    ],
    permissions=["read_env"],
    env_allowlist=["PATH", "HOME"],
)
```

---

### `SandboxStatus`

```python
class SandboxStatus(str, enum.Enum):
    created = "created"
    running = "running"
    stopped = "stopped"
    failed  = "failed"
```

Lifecycle state of a sandbox instance.

| Value | Meaning |
|---|---|
| `created` | Sandbox registered; no command has run yet |
| `running` | A command is currently executing |
| `stopped` | Last command completed (may be re-executed) |
| `failed` | An internal error occurred during execution |

---

### `SandboxResult`

```python
class SandboxResult(BaseModel):
    exit_code:      int            # process exit code; 0 = success
    stdout:         str            # default ""
    stderr:         str            # default ""
    duration_ms:    float          # wall-clock time in milliseconds, ge=0
    resource_usage: dict[str, Any] # default {}
```

Outcome of executing a command inside a sandbox.

**Fields:**

| Field | Type | Description |
|---|---|---|
| `exit_code` | `int` | Process exit code; 0 = success. -1 when killed by sandbox |
| `stdout` | `str` | Captured stdout (UTF-8 with replacement characters for invalid bytes) |
| `stderr` | `str` | Captured stderr. May contain a `[sandbox] killed: <reason>` suffix |
| `duration_ms` | `float` | Wall-clock execution time in milliseconds |
| `resource_usage` | `dict[str, Any]` | Keys: `cpu_seconds`, `peak_memory_mb`, `tokens_used`, `cost_usd`, `elapsed_seconds` |

**Example:**

```python
result: SandboxResult = manager.execute(sandbox_id, ["python", "-c", "print('hi')"])
print(result.exit_code)                        # 0
print(result.stdout)                           # hi\n
print(result.resource_usage["cpu_seconds"])    # 0.18
print(result.resource_usage["peak_memory_mb"]) # 22.4
```

---

## Core (`aumai_sandbox.core`)

### `SandboxError`

```python
class SandboxError(Exception): ...
```

Raised for sandbox lifecycle errors:
- Unknown `sandbox_id`
- Sandbox in wrong state (e.g. `running`) when `execute()` is called
- Empty command passed to `execute()`
- Shell metacharacters detected in `command[0]`

---

### `CapabilityParseError`

```python
class CapabilityParseError(Exception): ...
```

Raised when a capability YAML file or string cannot be parsed:
- File not found or not readable
- YAML syntax error
- Pydantic validation error on the parsed data

---

### `CapabilityParser`

```python
class CapabilityParser:
    @staticmethod
    def from_file(path: str | Path) -> CapabilityDeclaration: ...

    @staticmethod
    def from_string(yaml_text: str) -> CapabilityDeclaration: ...
```

Parse YAML capability files into `CapabilityDeclaration` objects.

#### `CapabilityParser.from_file`

```python
@staticmethod
def from_file(path: str | Path) -> CapabilityDeclaration
```

Load and parse a capability YAML file.

**Parameters:**
- `path` (`str | Path`) — Filesystem path to the YAML file.

**Returns:** A validated `CapabilityDeclaration`.

**Raises:** `CapabilityParseError` if the file cannot be read or fails validation.

**Example:**

```python
capability = CapabilityParser.from_file("config/capability.yaml")
```

#### `CapabilityParser.from_string`

```python
@staticmethod
def from_string(yaml_text: str) -> CapabilityDeclaration
```

Parse a YAML string into a `CapabilityDeclaration`.

**Parameters:**
- `yaml_text` (`str`) — Raw YAML content. An empty string or `null` produces a capability
  with all-default values.

**Returns:** A validated `CapabilityDeclaration`.

**Raises:** `CapabilityParseError` if the YAML is malformed or fails validation.

**Example:**

```python
capability = CapabilityParser.from_string("""
sandbox_tier: gvisor
resource_limits:
  max_memory_mb: 128
""")
```

---

### `SandboxManager`

```python
class SandboxManager:
    ISOLATION_WARNING: str
    def __init__(self) -> None: ...
    def create_sandbox(self, capability: CapabilityDeclaration) -> str: ...
    def execute(self, sandbox_id: str, command: list[str], timeout: float = 30.0) -> SandboxResult: ...
    def destroy(self, sandbox_id: str) -> None: ...
    def status(self, sandbox_id: str) -> SandboxStatus: ...
    def list_sandboxes(self) -> list[dict[str, Any]]: ...
```

Create, execute, and destroy isolated sandbox environments. Thread-safe.

#### `SandboxManager.__init__`

Creates an empty sandbox registry. Each `SandboxManager` instance maintains its own
in-process registry; sandboxes cannot be shared across instances.

#### `SandboxManager.create_sandbox`

```python
def create_sandbox(self, capability: CapabilityDeclaration) -> str
```

Register a new sandbox and return its unique ID.

**Parameters:**
- `capability` (`CapabilityDeclaration`) — Policy governing this sandbox.

**Returns:** A UUID4 string identifying the sandbox.

**Example:**

```python
sandbox_id = manager.create_sandbox(capability)
# "f47ac10b-58cc-4372-a567-0e02b2c3d479"
```

#### `SandboxManager.execute`

```python
def execute(
    self,
    sandbox_id: str,
    command: list[str],
    timeout: float = 30.0,
) -> SandboxResult
```

Run `command` inside the named sandbox and return the result.

**Parameters:**
- `sandbox_id` (`str`) — ID returned by `create_sandbox()`.
- `command` (`list[str]`) — Argv list, e.g. `["python", "agent.py", "--verbose"]`.
- `timeout` (`float`) — Wall-clock timeout in seconds. Default `30.0`.

**Returns:** `SandboxResult` with stdout, stderr, exit code, duration, and resource usage.

**Raises:**
- `SandboxError` — If `sandbox_id` is unknown, the sandbox is not in `created` or
  `stopped` state, `command` is empty, or `command[0]` contains shell metacharacters.

**Notes:**
- On non-Linux hosts or when `sandbox_tier=seccomp`, a `UserWarning` is issued.
- The resource monitor polls every 250 ms and kills the process if a limit is breached.
- When killed, a `[sandbox] killed: <reason>` line is appended to `stderr`.

**Example:**

```python
result = manager.execute(
    sandbox_id,
    ["python", "-c", "print('done')"],
    timeout=10.0,
)
```

#### `SandboxManager.destroy`

```python
def destroy(self, sandbox_id: str) -> None
```

Terminate and remove a sandbox. Kills any running process, then removes the sandbox
from the registry.

**Parameters:**
- `sandbox_id` (`str`) — ID of the sandbox to destroy.

**Raises:** `SandboxError` if `sandbox_id` does not exist.

#### `SandboxManager.status`

```python
def status(self, sandbox_id: str) -> SandboxStatus
```

Return the current `SandboxStatus` for the given sandbox.

**Raises:** `SandboxError` if `sandbox_id` does not exist.

#### `SandboxManager.list_sandboxes`

```python
def list_sandboxes(self) -> list[dict[str, Any]]
```

Return summary info for all tracked sandboxes.

**Returns:** List of dicts, each with keys `sandbox_id`, `status`, `tier`.

**Example:**

```python
for info in manager.list_sandboxes():
    print(info["sandbox_id"], info["status"], info["tier"])
```

---

## Network (`aumai_sandbox.network`)

### `EgressFilter`

```python
class EgressFilter:
    def __init__(self, rules: list[NetworkEgressRule]) -> None: ...
    def is_allowed(self, url: str) -> bool: ...
    def rules_for_domain(self, hostname: str) -> list[NetworkEgressRule]: ...
```

Validate outbound network requests against an allowlist of egress rules. A request is
allowed when at least one rule matches both the domain and the port. An empty rules list
denies all requests.

#### `EgressFilter.is_allowed`

```python
def is_allowed(self, url: str) -> bool
```

Return `True` if `url` is permitted by at least one egress rule.

**Parameters:**
- `url` (`str`) — Full URL, e.g. `"https://api.openai.com/v1/chat/completions"`.

**Returns:** `True` when allowed, `False` when denied or when `url` is malformed.

#### `EgressFilter.rules_for_domain`

```python
def rules_for_domain(self, hostname: str) -> list[NetworkEgressRule]
```

Return all rules whose domain pattern matches `hostname`.

### `check_egress` (module-level)

```python
def check_egress(url: str, rules: list[NetworkEgressRule]) -> bool
```

Return `True` when `url` is permitted by at least one rule.

**Parameters:**
- `url` (`str`) — Full URL to check.
- `rules` (`list[NetworkEgressRule]`) — Ordered list of rules. Empty = deny all.

**Example:**

```python
from aumai_sandbox import check_egress, NetworkEgressRule

rules = [NetworkEgressRule(domain="api.openai.com", ports=[443])]
print(check_egress("https://api.openai.com/v1/chat", rules))  # True
print(check_egress("https://malicious.io/steal", rules))      # False
```

---

## Filesystem (`aumai_sandbox.filesystem`)

### `FilesystemPolicy`

```python
class FilesystemPolicy:
    def __init__(self, config: FilesystemConfig) -> None: ...
    def can_read(self, path: str) -> bool: ...
    def can_write(self, path: str) -> bool: ...
    def deny_reason(self, path: str, mode: str) -> str | None: ...
```

Enforce read-only / read-write / no-access rules for path access. Logic-layer checks
only — does not perform OS-level isolation.

#### `FilesystemPolicy.can_read`

```python
def can_read(self, path: str) -> bool
```

Return `True` when `path` may be read under this policy.

#### `FilesystemPolicy.can_write`

```python
def can_write(self, path: str) -> bool
```

Return `True` when `path` may be written under this policy.

#### `FilesystemPolicy.deny_reason`

```python
def deny_reason(self, path: str, mode: str) -> str | None
```

Return a human-readable denial reason, or `None` if access is allowed.

**Parameters:**
- `path` (`str`) — Path to evaluate.
- `mode` (`str`) — `"read"` or `"write"`.

### `validate_path_access` (module-level)

```python
def validate_path_access(path: str, mode: str, config: FilesystemConfig) -> bool
```

Return `True` when `path` is accessible in `mode` under `config`.

**Parameters:**
- `path` (`str`) — Filesystem path to evaluate (need not exist).
- `mode` (`str`) — `"read"` or `"write"`.
- `config` (`FilesystemConfig`) — Policy to evaluate against.

**Returns:** `True` if the operation is permitted.

**Raises:** `ValueError` if `mode` is not `"read"` or `"write"`.

**Example:**

```python
from aumai_sandbox import FilesystemConfig, FilesystemMode, validate_path_access

config = FilesystemConfig(mode=FilesystemMode.read_write, writable_paths=["/tmp/work"])
print(validate_path_access("/etc/hosts", "read", config))          # True
print(validate_path_access("/etc/hosts", "write", config))         # False
print(validate_path_access("/tmp/work/out.json", "write", config)) # True
```

---

## Resources (`aumai_sandbox.resources`)

### `ResourceMonitor`

```python
class ResourceMonitor:
    def __init__(self, limits: ResourceLimits) -> None: ...
    def start(self, pid: int | None = None) -> None: ...
    def stop(self) -> None: ...
    def record_tokens(self, count: int) -> None: ...
    def record_cost(self, amount_usd: float) -> None: ...
    def record_memory(self, memory_mb: float) -> None: ...
    def snapshot(self) -> dict[str, Any]: ...
    def check_limits(self) -> tuple[bool, str | None]: ...
```

Track CPU time, memory, token spend, and USD cost for a sandbox. Runs a background
polling thread every 250 ms using `psutil` when available.

#### `ResourceMonitor.__init__`

**Parameters:**
- `limits` (`ResourceLimits`) — Thresholds to enforce.

#### `ResourceMonitor.start`

```python
def start(self, pid: int | None = None) -> None
```

Begin monitoring. Optionally attach to `pid` for OS-level metrics.

#### `ResourceMonitor.stop`

Stop the background polling thread. Call in a `finally` block to avoid thread leaks.

#### `ResourceMonitor.record_tokens`

```python
def record_tokens(self, count: int) -> None
```

Add `count` to the running token total. Call this after each LLM API response.

#### `ResourceMonitor.record_cost`

```python
def record_cost(self, amount_usd: float) -> None
```

Add `amount_usd` to the running cost total.

#### `ResourceMonitor.record_memory`

```python
def record_memory(self, memory_mb: float) -> None
```

Update peak memory if `memory_mb` exceeds the current peak.

#### `ResourceMonitor.snapshot`

```python
def snapshot(self) -> dict[str, Any]
```

Return a point-in-time snapshot of all tracked metrics.

**Returns:** Dict with keys:
- `cpu_seconds` (`float`) — Cumulative CPU time (user + system)
- `peak_memory_mb` (`float`) — Peak RSS in MiB
- `tokens_used` (`int`) — Total tokens recorded
- `cost_usd` (`float`) — Total cost in USD
- `elapsed_seconds` (`float`) — Wall-clock time since `start()`

#### `ResourceMonitor.check_limits`

```python
def check_limits(self) -> tuple[bool, str | None]
```

Return `(within_limits, violation_message)`.

**Returns:**
- `(True, None)` — All metrics within limits.
- `(False, "CPU limit exceeded: 12.43s used, limit is 10.00s")` — First breached limit.

### `check_limits` (module-level)

```python
def check_limits(
    current: dict[str, Any],
    limits: ResourceLimits,
) -> tuple[bool, str | None]
```

Check a snapshot dict against `ResourceLimits` thresholds.

**Parameters:**
- `current` (`dict`) — Keys: `cpu_seconds`, `peak_memory_mb`, `tokens_used`, `cost_usd`.
  Missing keys are treated as 0.
- `limits` (`ResourceLimits`) — Thresholds to check against.

**Returns:** `(True, None)` or `(False, human_readable_reason)`.

**Example:**

```python
from aumai_sandbox import ResourceLimits, check_limits

limits = ResourceLimits(max_cpu_seconds=10.0, max_memory_mb=512)
ok, reason = check_limits(
    {"cpu_seconds": 5.0, "peak_memory_mb": 400},
    limits,
)
print(ok, reason)  # True None

ok, reason = check_limits(
    {"cpu_seconds": 15.0, "peak_memory_mb": 400},
    limits,
)
print(ok, reason)  # False "CPU limit exceeded: 15.00s used, limit is 10.00s"
```
