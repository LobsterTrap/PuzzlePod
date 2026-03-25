%global project_name   puzzlepod

%if 0%{?commit:1}
%global source_name    %{project_name}-%{commit}
%global rpm_release    0.%{commitdate}.git%{shortcommit}%{?dist}
%else
%global source_name    %{project_name}-%{version}
%global rpm_release    1%{?dist}
%endif

Name:           puzzle-podman
Version:        0.1.0
Release:        %{rpm_release}
Summary:        Podman integration for PuzzlePod
License:        Apache-2.0
URL:            https://github.com/LobsterTrap/PuzzlePod
Source0:        %{source_name}.tar.gz
BuildArch:      noarch

Requires:       puzzled = %{version}-%{release}
Requires:       podman >= 5.0

%description
Podman integration for PuzzlePod, enabling agent branching for container
workloads. Provides:

  - puzzle-podman helper script for OCI prestart/poststop hooks
  - OCI hook configuration for automatic branch creation on container start
  - Support for podman run --puzzle-branch
  - Support for Quadlet AgentBranch=true directive
  - podman agent subcommands: inspect, approve, reject, list

%prep
%autosetup -n %{source_name}

%install
install -D -m 0755 podman/puzzle-podman %{buildroot}%{_libexecdir}/puzzle-podman
install -D -m 0644 podman/hooks/puzzle-branch.json \
    %{buildroot}%{_datadir}/containers/oci/hooks.d/puzzle-branch.json

%files
%license LICENSE
%doc README.md
%{_libexecdir}/puzzle-podman
%{_datadir}/containers/oci/hooks.d/puzzle-branch.json

%changelog
* Mon Mar 09 2026 Francis Chow <fchow@redhat.com> - 0.1.0-1
- Add git snapshot macros for COPR pre-release builds

* Sat Mar 07 2026 Francis Chow <fchow@redhat.com> - 0.1.0-0
- Initial package
