%global project_name   puzzlepod

%if 0%{?commit:1}
%global rpm_release    0.%{commitdate}.git%{shortcommit}%{?dist}
%else
%global rpm_release    1%{?dist}
%endif

Name:           puzzlepod
Version:        0.1.0
Release:        %{rpm_release}
Summary:        PuzzlePod — kernel-enforced guardrails for AI agents (meta-package)
License:        Apache-2.0
URL:            https://github.com/LobsterTrap/PuzzlePod
BuildArch:      noarch

Requires:       puzzled = %{version}-%{release}
Requires:       puzzlectl = %{version}-%{release}
Requires:       puzzled-selinux = %{version}-%{release}
Requires:       puzzled-profiles = %{version}-%{release}
Requires:       puzzled-policies = %{version}-%{release}

# puzzlepod-minimal: core only (no podman, no SELinux)
%package -n     puzzlepod-minimal
Summary:        PuzzlePod minimal install (daemon + CLI + policies)
Requires:       puzzled = %{version}-%{release}
Requires:       puzzlectl = %{version}-%{release}
Requires:       puzzled-profiles = %{version}-%{release}
Requires:       puzzled-policies = %{version}-%{release}

%description -n puzzlepod-minimal
Minimal PuzzlePod install: puzzled daemon, puzzlectl CLI, default profiles
and policies. Does not include SELinux policy or Podman integration.
Suitable for development, testing, and non-SELinux deployments.

%description
Meta-package that installs the complete PuzzlePod stack for kernel-enforced
AI agent governance on Linux. This includes:

  puzzled          - Governance daemon managing agent sandbox lifecycles
  puzzlectl        - Command-line management tool
  puzzled-selinux  - SELinux policy module for mandatory access control
  puzzled-profiles - Pre-built agent profiles (restricted, standard, privileged)
  puzzled-policies - OPA/Rego governance policies for commit evaluation

PuzzlePod uses only existing kernel primitives (Landlock, seccomp-BPF,
namespaces, cgroups, OverlayFS, SELinux) — no kernel modifications required.
All enforcement is kernel-level and irrevocable by the agent process.

Targets RHEL 10+, Fedora 42+, and CentOS Stream 10 on x86_64 and aarch64.

%files
# Meta-package — no files, only dependencies

%files -n puzzlepod-minimal
# Meta-package — no files, only dependencies

%changelog
* Mon Mar 09 2026 Francis Chow <fchow@redhat.com> - 0.1.0-1
- Add puzzlepod-minimal sub-package
- Remove puzzle-podman from default meta-package (install separately)
- Add git snapshot macros for COPR pre-release builds

* Sat Mar 07 2026 Francis Chow <fchow@redhat.com> - 0.1.0-0
- Initial meta-package
