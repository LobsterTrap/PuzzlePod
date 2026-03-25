%global project_name   puzzlepod

%if 0%{?commit:1}
%global source_name    %{project_name}-%{commit}
%global rpm_release    0.%{commitdate}.git%{shortcommit}%{?dist}
%else
%global source_name    %{project_name}-%{version}
%global rpm_release    1%{?dist}
%endif

Name:           puzzled-selinux
Version:        0.1.0
Release:        %{rpm_release}
Summary:        SELinux policy module for PuzzlePod
License:        Apache-2.0
URL:            https://github.com/LobsterTrap/PuzzlePod
Source0:        %{source_name}.tar.gz
BuildArch:      noarch

BuildRequires:  selinux-policy-devel
BuildRequires:  make

Requires:       selinux-policy-targeted
Requires(post): selinux-policy-targeted
Requires(post): policycoreutils
Requires(post): policycoreutils-python-utils
Requires(postun): policycoreutils

%description
SELinux policy module for the PuzzlePod governance daemon and agent
sandboxes. Defines mandatory access control types and rules:

  puzzlepod_t       - Daemon domain for the puzzled governance daemon
  puzzlepod_t    - Sandboxed agent process domain
  puzzlepod_branch_t - Branch filesystem type for OverlayFS upper layers
  puzzlectl_t     - CLI tool domain for puzzlectl

Includes neverallow rules preventing agents from accessing system files,
using ptrace, loading kernel modules, or modifying SELinux policy.

%prep
%autosetup -n %{source_name}

%build
cd selinux
make -f /usr/share/selinux/devel/Makefile puzzlepod.pp

%install
install -D -m 0644 selinux/puzzlepod.pp %{buildroot}%{_datadir}/selinux/packages/puzzlepod.pp
install -D -m 0644 selinux/puzzlepod.if %{buildroot}%{_datadir}/selinux/devel/include/contrib/puzzlepod.if
install -D -m 0644 selinux/puzzlepod.fc %{buildroot}%{_datadir}/selinux/devel/include/contrib/puzzlepod.fc

%post
semodule -i %{_datadir}/selinux/packages/puzzlepod.pp 2>/dev/null || :
fixfiles -R puzzled restore 2>/dev/null || :
restorecon -R %{_sbindir}/puzzled %{_bindir}/puzzlectl \
    %{_sharedstatedir}/puzzled 2>/dev/null || :

%postun
if [ $1 -eq 0 ]; then
    semodule -r puzzlepod 2>/dev/null || :
    fixfiles -R puzzled restore 2>/dev/null || :
fi

%files
%license LICENSE
%{_datadir}/selinux/packages/puzzlepod.pp
%{_datadir}/selinux/devel/include/contrib/puzzlepod.if
%{_datadir}/selinux/devel/include/contrib/puzzlepod.fc

%changelog
* Mon Mar 09 2026 Francis Chow <fchow@redhat.com> - 0.1.0-1
- Add file context file (.fc) to package
- Add restorecon in post for binary and state paths
- Add git snapshot macros for COPR pre-release builds

* Sat Mar 07 2026 Francis Chow <fchow@redhat.com> - 0.1.0-0
- Initial package
