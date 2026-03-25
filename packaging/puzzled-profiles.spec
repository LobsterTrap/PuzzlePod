%global project_name   puzzlepod

%if 0%{?commit:1}
%global source_name    %{project_name}-%{commit}
%global rpm_release    0.%{commitdate}.git%{shortcommit}%{?dist}
%else
%global source_name    %{project_name}-%{version}
%global rpm_release    1%{?dist}
%endif

Name:           puzzled-profiles
Version:        0.1.0
Release:        %{rpm_release}
Summary:        Agent profiles for PuzzlePod
License:        Apache-2.0
URL:            https://github.com/LobsterTrap/PuzzlePod
Source0:        %{source_name}.tar.gz
BuildArch:      noarch

Requires:       puzzled = %{version}-%{release}

%description
Pre-built agent profiles for the PuzzlePod governance daemon. Profiles
define per-agent access control including filesystem read/write allowlists
and denylists, executable allowlists, resource limits, network mode and
domain lists, behavioral trigger configuration, and fail mode.

Included profiles:
  restricted  - Minimal access, no network, small quotas
  standard    - Project-scoped access, gated network, standard quotas
  privileged  - Broad access, monitored network, large quotas

Additional profiles for common workloads: code-assistant, ci-runner,
data-analyst, web-scraper, ml-training, security-scanner, and more.

%prep
%autosetup -n %{source_name}

%install
install -d %{buildroot}%{_sysconfdir}/puzzled/profiles
install -m 0644 policies/profiles/*.yaml %{buildroot}%{_sysconfdir}/puzzled/profiles/

# JSON schema for profile validation
install -D -m 0644 policies/schemas/profile.schema.json \
    %{buildroot}%{_datadir}/puzzled/schemas/profile.schema.json

# Man page
install -D -m 0644 man/puzzlepod-profile.5 %{buildroot}%{_mandir}/man5/puzzlepod-profile.5

%files
%license LICENSE
%dir %{_sysconfdir}/puzzled/profiles
%config(noreplace) %{_sysconfdir}/puzzled/profiles/*.yaml
%dir %{_datadir}/puzzled
%dir %{_datadir}/puzzled/schemas
%{_datadir}/puzzled/schemas/profile.schema.json
%{_mandir}/man5/puzzlepod-profile.5*

%changelog
* Mon Mar 09 2026 Francis Chow <fchow@redhat.com> - 0.1.0-1
- Add JSON schema for profile validation
- Add git snapshot macros for COPR pre-release builds

* Sat Mar 07 2026 Francis Chow <fchow@redhat.com> - 0.1.0-0
- Initial package
