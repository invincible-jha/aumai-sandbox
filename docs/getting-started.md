# Getting Started with aumai-sandbox

This guide walks you from zero to a running sandboxed agent in under five minutes, then
covers common patterns you will encounter in production.

---

## Prerequisites

- Python 3.11 or newer
- `pip` (comes with Python)
- A terminal / command prompt

Optional but recommended:
- `psutil` for accurate CPU and memory metrics (installed via the `[psutil]` extra)
- Linux with [gVisor](https://gvisor.dev) for kernel-level isolation beyond subprocess

---

## Installation

### From PyPI (recommended)

```bash
pip install aumai-sandbox
```

With accurate resource metrics:

```bash
pip install "aumai-sandbox[psutil]"
```

### From source

```bash
git clone https://github.com/aumai/aumai-sandbox.git
cd aumai-sandbox
pip install -e .
```

### Development mode (with test dependencies)

```bash
git clone https://github.com/aumai/aumai-sandbox.git
cd aumai-sandbox
pip install -e ".[dev]"
```

Verify your installation:

```bash
aumai-sandbox --version
python -c "import aumai_sandbox; print(aumai_sandbox.__version__)"
```

---

## Your First Sandbox

This tutorial creates a capability, launches a sandbox, runs a command, and inspects the
result. Each step takes about 30 seconds.

### Step 1 — Write a capability file

A capability file is a YAML document that declares what the sandboxed agent is allowed to
do. Create a file called `my_capability.yaml`:

```yaml
# my_capability.yaml

# How much isolation to apply.
# "seccomp" is the portable default; works everywhere Python runs.
sandbox_tier: seccomp

# Hard resource limits. The process is killed if any limit is breached.
resource_limits:
  max_memory_mb: 256       # kill if process exceeds 256 MiB RSS
  max_cpu_seconds: 10.0    # kill if process uses more than 10 CPU seconds
  max_cost_usd: 0.05       # halt if LLM API spend exceeds $0.05
  max_tokens: 50000        # halt if token usage exceeds 50,000

# Which outbound domains the agent may contact.
# An empty list means no outbound connections are permitted.
network_egress_rules:
  - domain: "api.openai.com"
    ports: [443]
    rate_limit_per_min: 30

# File system access mode for the agent.
filesystem_config:
  mode: read_only

# Named capability tokens granted to this agent.
# "read_env" allows the agent to inherit environment variables
# (after sensitive-key filtering).
permissions:
  - read_env

# Further restrict which env vars survive (optional).
env_allowlist:
  - PATH
  - PYTHONPATH
  - HOME
```

### Step 2 — Validate the capability file

Before running anything, verify that the YAML is syntactically and semantically valid:

```bash
aumai-sandbox validate --config my_capability.yaml
```

Expected output:
```
VALID
  sandbox_tier       : seccomp
  filesystem_mode    : read_only
  max_memory_mb      : 256
  max_cpu_seconds    : 10.0
  max_cost_usd       : 0.05
  max_tokens         : 50000
  egress_rules       : 1
  permissions        : read_env
```

Exit code 0 means valid. Exit code 1 means something is wrong — the error message will
tell you exactly which field failed.

### Step 3 — Run a command

```bash
aumai-sandbox run --config my_capability.yaml -- python -c "print('hello from sandbox')"
```

You should see:
```
[sandbox] created  id=<uuid>  tier=seccomp
[sandbox] running  $ python -c print('hello from sandbox')
hello from sandbox
[sandbox] finished  exit=0  duration=234ms  cpu=0.18s  mem=22.4MiB
```

The agent's stdout is forwarded to your terminal. The summary line (in green or red) goes
to stderr so it does not mix with agent output when you redirect stdout.

### Step 4 — Run from Python

```python
from aumai_sandbox import CapabilityParser, SandboxManager

capability = CapabilityParser.from_file("my_capability.yaml")
manager = SandboxManager()
sandbox_id = manager.create_sandbox(capability)

result = manager.execute(
    sandbox_id,
    ["python", "-c", "import platform; print(platform.python_version())"],
    timeout=30.0,
)
manager.destroy(sandbox_id)

print("exit_code:", result.exit_code)
print("stdout   :", result.stdout.strip())
print("duration :", result.duration_ms, "ms")
print("usage    :", result.resource_usage)
```

---

## Common Patterns

### Pattern 1 — Minimal sandbox (no network, read-only fs)

Use this for agents that only need to process data passed as arguments or stdin — no
external calls, no file writes.

```python
from aumai_sandbox import CapabilityDeclaration, ResourceLimits, SandboxManager

manager = SandboxManager()
capability = CapabilityDeclaration(
    resource_limits=ResourceLimits(max_cpu_seconds=5.0, max_memory_mb=128),
    # network_egress_rules defaults to [] — deny all outbound
    # filesystem_config defaults to FilesystemConfig(mode=FilesystemMode.read_only)
    # permissions defaults to [] — no env inheritance
)
sandbox_id = manager.create_sandbox(capability)
result = manager.execute(sandbox_id, ["python", "process_data.py", "--input", "data.json"])
manager.destroy(sandbox_id)
```

### Pattern 2 — Agent with controlled write access

Allow the agent to write output to a specific temporary directory.

```python
from aumai_sandbox import (
    CapabilityDeclaration,
    FilesystemConfig,
    FilesystemMode,
    SandboxManager,
)

manager = SandboxManager()
capability = CapabilityDeclaration(
    filesystem_config=FilesystemConfig(
        mode=FilesystemMode.read_write,
        writable_paths=["/tmp/agent_output"],
    ),
)
sandbox_id = manager.create_sandbox(capability)
result = manager.execute(
    sandbox_id,
    ["python", "agent.py", "--output-dir", "/tmp/agent_output"],
)
manager.destroy(sandbox_id)
```

### Pattern 3 — LLM agent with spend tracking

Track token and cost usage when your agent makes LLM API calls. Record usage after each
call so the resource monitor can enforce the cap.

```python
from aumai_sandbox import (
    CapabilityDeclaration,
    NetworkEgressRule,
    ResourceLimits,
    SandboxManager,
)
from aumai_sandbox.resources import ResourceMonitor

limits = ResourceLimits(max_tokens=10_000, max_cost_usd=0.10)
monitor = ResourceMonitor(limits)
monitor.start()

# After each LLM call in your agent code:
monitor.record_tokens(750)
monitor.record_cost(0.0075)

within_limits, reason = monitor.check_limits()
if not within_limits:
    print(f"Limit breached: {reason}")

monitor.stop()
print("Usage:", monitor.snapshot())
```

### Pattern 4 — Reuse a sandbox for multiple commands

A sandbox can be executed multiple times after being stopped. Status transitions:
`created` → `running` → `stopped` → `running` → `stopped` ...

```python
from aumai_sandbox import CapabilityDeclaration, SandboxManager

manager = SandboxManager()
sandbox_id = manager.create_sandbox(CapabilityDeclaration())

commands = [
    ["python", "-c", "print('step 1')"],
    ["python", "-c", "print('step 2')"],
    ["python", "-c", "print('step 3')"],
]

for cmd in commands:
    result = manager.execute(sandbox_id, cmd, timeout=10.0)
    print(f"stdout: {result.stdout.strip()}, exit: {result.exit_code}")

manager.destroy(sandbox_id)
```

### Pattern 5 — Validate a YAML file in CI

Add this to your CI pipeline to reject capability regressions (e.g. someone accidentally
removing a resource limit):

```bash
aumai-sandbox validate --config capability.yaml --output json | python -c "
import json, sys
data = json.load(sys.stdin)
if not data['valid']:
    print('FAIL:', data['error'])
    sys.exit(1)
limits = data['capability']['resource_limits']
assert limits['max_memory_mb'] <= 512, 'memory limit too high'
assert limits['max_cost_usd'] <= 0.10, 'cost limit too high'
print('Capability validated OK')
"
```

---

## Troubleshooting FAQ

**Q: I get a `SandboxError: unknown sandbox id` error.**

The sandbox ID was not found in the manager's in-process registry. This usually means you
are creating the sandbox in one `SandboxManager` instance and calling `execute` on a
different instance. Each `SandboxManager` has its own registry. Use the same instance
throughout a session.

---

**Q: I see `UserWarning: No kernel-level isolation is enforced...`**

This warning fires whenever `aumai-sandbox` runs on a non-Linux host or when the
`seccomp` tier is selected. It is informational — the sandbox still applies environment
filtering, resource limits, and policy checks. For production deployments requiring full
kernel isolation, use Linux with gVisor (`sandbox_tier: gvisor`) and `runsc` installed.

To silence the warning in tests:

```python
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="aumai_sandbox")
```

---

**Q: Resource usage shows `cpu_seconds: 0` even though the agent ran for a while.**

`psutil` is not installed. Install it with `pip install "aumai-sandbox[psutil]"` (or
`pip install psutil`) to enable accurate CPU and memory sampling. Without `psutil`, the
monitor still runs but records zero for OS-level metrics; wall-clock elapsed time is used
as a fallback.

---

**Q: The process was killed but I do not see which limit was breached.**

Check `result.stderr` — when the resource monitor kills a process, it appends a line like:

```
[sandbox] killed: CPU limit exceeded: 12.43s used, limit is 10.00s
```

Also check `result.resource_usage` for the snapshot taken at kill time.

---

**Q: `CapabilityParseError: capability validation error` — what does it mean?**

The YAML file is syntactically valid YAML but failed Pydantic model validation. The error
message includes the full Pydantic error report. Common causes:

- A port number outside the 1–65535 range in `network_egress_rules`.
- `writable_paths` specified when `mode` is not `read_write`.
- A negative or zero `max_memory_mb`.
- An unrecognized `sandbox_tier` value (valid values: `seccomp`, `gvisor`, `firecracker`).

---

**Q: Can I use aumai-sandbox on Windows?**

Yes. The package runs on Windows. Kernel-level isolation (gVisor, seccomp filters) is not
available on Windows, so the sandbox runs in subprocess-with-filtered-environment mode
regardless of the `sandbox_tier` setting. The isolation warning is issued automatically.
All resource limits, environment filtering, and policy checks still apply.

---

**Q: How do I pass environment variables to the agent?**

Two options:

1. Add `read_env` to `permissions` — the agent inherits the full filtered environment
   (sensitive keys are always removed).
2. Combine `read_env` with `env_allowlist` — only the explicitly listed variable names
   pass through (after sensitive-key filtering).

```yaml
permissions:
  - read_env
env_allowlist:
  - PATH
  - HOME
  - MY_CUSTOM_CONFIG
```

---

## Next Steps

- Read the [API Reference](api-reference.md) for full class and method documentation.
- Explore the [examples/](../examples/) directory for runnable demo scripts.
- See the main [README](../README.md) for architecture diagrams and integration guides.
