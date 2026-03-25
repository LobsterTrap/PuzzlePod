# Kubernetes Sandboxing vs. PuzzlePod

## The Challenge

"Kubernetes platforms already provide sandboxes. Why do we need PuzzlePod?"

## The Short Answer

Kubernetes isolates **containers from each other**. PuzzlePod governs **an AI agent from itself**. They solve fundamentally different problems and are complementary, not competing.

## What "K8s Sandbox" Actually Means

When people refer to Kubernetes sandboxing, they typically mean one of four things:

| Mechanism | What It Does | What It Doesn't Do |
|---|---|---|
| **Container isolation** (namespaces, cgroups, seccomp) | Isolates a pod from other pods and the host | No governance of what happens inside the container |
| **gVisor (runsc)** | User-space kernel that intercepts and re-implements syscalls in a sandboxed process | No changeset review, no commit/rollback, significant per-syscall overhead |
| **Kata Containers** | Runs each pod inside a lightweight VM for stronger isolation | No awareness of workload behavior, no filesystem branching |
| **OPA Gatekeeper / Pod Security Standards** | Admission control governing what pods can be *created* (e.g., no privileged mode, no host networking) | Does not govern what a running process does after admission |

In all four cases, the pattern is the same: **they control the boundary, not the behavior inside it**. None of them provide filesystem branching, structured diff review, or commit/rollback governance.

## Key Differentiators

### 1. Isolation vs. Governance

Kubernetes answers: *"Can this pod talk to that pod?"*

PuzzlePod answers: *"Should this agent's actions be committed to reality?"*

Kubernetes has no concept of **Fork, Explore, Commit**. There is no mechanism to let a workload run speculatively in a copy-on-write filesystem branch, review a structured diff of everything it changed, evaluate that diff against OPA/Rego governance policy, and then atomically commit or rollback with zero residue. Kubernetes containers are either running or not — there is no governance checkpoint between "the work happened" and "the work persists."

### 2. Trusted Code vs. Untrusted Control Flow

Kubernetes assumes the code inside the container is **deterministic** — it was built, tested, and deployed through a CI/CD pipeline. The syscall sequence is known at design time.

An agentic workload is fundamentally different. The LLM decides *at runtime* which files to open, which binaries to execute, which network connections to initiate. It combines:

- The **broad syscall surface** of an interactive shell
- The **autonomous execution** of a daemon
- The **untrusted control flow** of arbitrary user input

No Kubernetes primitive addresses this combination. Kubernetes was designed for microservices with predictable behavior, not for workloads whose next action is determined by a probabilistic model.

### 3. Wrong Granularity

Kubernetes operates at the **pod boundary**. An AI agent inside a pod might spawn dozens of subprocesses — `gcc`, `curl`, `rm`, `python`, `git` — and Kubernetes does not gate individual `execve()` or `connect()` calls within a running pod.

PuzzlePod intercepts these low-frequency, high-risk syscalls via seccomp `USER_NOTIF` and evaluates each against policy in real-time. It also applies Landlock filesystem ACLs, BPF LSM hooks for exec counting and rate limiting, and fanotify monitoring for behavioral anomaly detection — all within the running process, not at the pod boundary.

### 4. Edge and Safety-Critical Deployments

A functional Kubernetes cluster (etcd, API server, controller-manager, scheduler, kubelet, container runtime, CNI plugin) requires a minimum of approximately **8GB RAM**. This makes it impractical for resource-constrained edge environments.

PuzzlePod is a **single daemon** designed to run on edge devices with **4GB of RAM or below** — robots, drones, vehicles, industrial controllers. There is no distributed control plane, no etcd consensus, no API server. The enforcement is performed by existing kernel primitives (Landlock, seccomp, namespaces, cgroups) with deterministic latency under 1 microsecond.

For safety-critical deployments, PuzzlePod is designed for **certification compatibility** (IEC 61508, ISO 26262) with deterministic behavior and no garbage collection pauses. Kubernetes is not certifiable for safety-critical systems.

### 5. Kernel-Enforced and Agent-Irrevocable

Kubernetes security policies (NetworkPolicy, Pod Security Standards, OPA Gatekeeper) operate at the **API server level** — they govern what pods can be *created*, not what running processes can *do*. If the kubelet or API server becomes unavailable, enforcement may be affected.

PuzzlePod attaches Landlock rulesets and seccomp-BPF filters **directly to the agent process via the kernel**. These are irrevocable — they survive even if the `puzzled` daemon crashes. The agent process literally cannot remove its own restrictions. This is the difference between a policy enforced by an external service and a restriction embedded in the process itself by the kernel.

### 6. Complementary, Not Competing

Kubernetes and PuzzlePod work at different layers and are designed to compose together.

In practice, you run the agent in a container (Kubernetes provides infrastructure isolation) **and** with PuzzlePod branch governance (PuzzlePod governs what the agent does within its sandbox). This is what `podman run --puzzle-branch` enables. Kubernetes keeps the agent away from other workloads; PuzzlePod governs the agent's own actions.

Asking why we need both is like asking why we need application-layer firewalls when we already have network firewalls.

## Summary

| Concern | Kubernetes | PuzzlePod |
|---|---|---|
| **Problem** | Isolate workloads from each other | Govern an AI agent's behavior |
| **Trust model** | Trusted code, deterministic control flow | Trusted identity, untrusted control flow |
| **Granularity** | Pod boundary | Per-syscall (execve, connect, bind) |
| **Filesystem** | Ephemeral container layers | CoW branching with diff/commit/rollback |
| **Governance** | Admission control (pre-creation) | Runtime behavioral governance |
| **Enforcement** | API server + kubelet | Kernel-enforced, agent-irrevocable |
| **Minimum footprint** | ~8GB RAM | 4GB RAM or below |
| **Safety certification** | Not applicable | IEC 61508 / ISO 26262 compatible |
| **Relationship** | Infrastructure layer | Workload governance layer (composes with K8s) |
