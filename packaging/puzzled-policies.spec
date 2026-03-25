%global project_name   puzzlepod

%if 0%{?commit:1}
%global source_name    %{project_name}-%{commit}
%global rpm_release    0.%{commitdate}.git%{shortcommit}%{?dist}
%else
%global source_name    %{project_name}-%{version}
%global rpm_release    1%{?dist}
%endif

Name:           puzzled-policies
Version:        0.1.0
Release:        %{rpm_release}
Summary:        OPA/Rego governance policies for PuzzlePod
License:        Apache-2.0
URL:            https://github.com/LobsterTrap/PuzzlePod
Source0:        %{source_name}.tar.gz
BuildArch:      noarch

Requires:       puzzled = %{version}-%{release}

%description
OPA/Rego governance policies for the PuzzlePod governance daemon.
Policies are evaluated at commit time to determine whether an agent's
changes should be applied to the base filesystem.

Default commit rules enforce:
  - No sensitive files (credentials, SSH keys, .env) in changeset
  - No persistence mechanisms (cron jobs, systemd units)
  - No executable permission changes
  - Total changeset size within limits
  - No system file modifications
  - Maximum file count per changeset

%prep
%autosetup -n %{source_name}

%install
install -d %{buildroot}%{_sysconfdir}/puzzled/policies
install -m 0644 policies/rules/*.rego %{buildroot}%{_sysconfdir}/puzzled/policies/

%files
%license LICENSE
%dir %{_sysconfdir}/puzzled/policies
%config(noreplace) %{_sysconfdir}/puzzled/policies/*.rego

%changelog
* Mon Mar 09 2026 Francis Chow <fchow@redhat.com> - 0.1.0-1
- Add git snapshot macros for COPR pre-release builds

* Sat Mar 07 2026 Francis Chow <fchow@redhat.com> - 0.1.0-0
- Initial package
