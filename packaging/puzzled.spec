# To build a git snapshot RPM for COPR:
#   export commit=$(git rev-parse HEAD)
#   export shortcommit=$(git rev-parse --short HEAD)
#   export commitdate=$(date +%Y%m%d -d @$(git show -s --format=%ct HEAD))
#   git archive --prefix=puzzlepod-${commit}/ HEAD | gzip > puzzlepod-${commit}.tar.gz
#   rpmbuild -bs puzzled.spec --define "commit ${commit}" --define "shortcommit ${shortcommit}" --define "commitdate ${commitdate}"

# Disable debug packages — Rust debug source handling is inconsistent
# across distros: empty debugsourcefiles.list on RHEL 10, unpackaged
# debug sources on Fedora 42.
%global debug_package %{nil}

%global project_name   puzzlepod

# Git snapshot support — define commit, shortcommit, commitdate externally
# for pre-release builds. When unset, builds as a tagged release.
%if 0%{?commit:1}
%global source_name    %{project_name}-%{commit}
%global rpm_release    0.%{commitdate}.git%{shortcommit}%{?dist}
%else
%global source_name    %{project_name}-%{version}
%global rpm_release    1%{?dist}
%endif

Name:           puzzled
Version:        0.1.0
Release:        %{rpm_release}
Summary:        PuzzlePod governance daemon
License:        Apache-2.0
URL:            https://github.com/LobsterTrap/PuzzlePod
Source0:        %{source_name}.tar.gz

ExclusiveArch:  x86_64 aarch64

BuildRequires:  rust >= 1.75
BuildRequires:  cargo >= 1.75
BuildRequires:  git-core
BuildRequires:  systemd-rpm-macros
BuildRequires:  libseccomp-devel
BuildRequires:  dbus-devel
BuildRequires:  clang
BuildRequires:  llvm
BuildRequires:  openssl-devel

Requires:       systemd
Requires:       dbus
Requires:       libseccomp
Requires(pre):  shadow-utils

%description
PuzzlePod governance daemon (puzzled) provides kernel-enforced guardrails
for autonomous AI agents on Linux. It composes existing kernel primitives
(Landlock, seccomp-BPF, namespaces, cgroups, OverlayFS, SELinux) into
isolated sandboxes, implementing a Fork-Explore-Commit workflow with
OPA/Rego policy evaluation for commit governance.

puzzled runs as a system daemon, managing agent sandbox lifecycles via
D-Bus, and enforces containment that is irrevocable by the agent process.

%prep
%autosetup -n %{source_name}
# regorus build.rs requires git rev-parse HEAD (opa-runtime feature)
git init -q && git add -A && git -c user.name=build -c user.email=build@rpm commit -q -m "rpm build" --allow-empty

%build
cargo build --release --bin puzzled

%install
install -D -m 0755 target/release/puzzled %{buildroot}%{_sbindir}/puzzled

# systemd units
install -D -m 0644 systemd/puzzled.service %{buildroot}%{_unitdir}/puzzled.service
install -D -m 0644 systemd/puzzle@.service %{buildroot}%{_unitdir}/puzzle@.service
install -D -m 0644 systemd/puzzle.slice %{buildroot}%{_unitdir}/puzzle.slice

# Configuration
install -D -m 0640 config/puzzled.conf.example %{buildroot}%{_sysconfdir}/puzzled/puzzled.conf

# D-Bus interface definition + bus policy
install -D -m 0644 dbus/org.lobstertrap.PuzzlePod1.Manager.xml \
    %{buildroot}%{_datadir}/dbus-1/interfaces/org.lobstertrap.PuzzlePod1.Manager.xml
install -D -m 0644 dbus/org.lobstertrap.PuzzlePod1.conf \
    %{buildroot}%{_sysconfdir}/dbus-1/system.d/org.lobstertrap.PuzzlePod1.conf

# tmpfiles.d for /run/puzzled (runtime state directory)
install -d %{buildroot}%{_tmpfilesdir}
cat > %{buildroot}%{_tmpfilesdir}/puzzled.conf <<'EOF'
d /run/puzzled 0750 root puzzled -
EOF

# Man pages
install -D -m 0644 man/puzzled.8 %{buildroot}%{_mandir}/man8/puzzled.8
install -D -m 0644 man/puzzled.conf.5 %{buildroot}%{_mandir}/man5/puzzled.conf.5

# State directories
install -d %{buildroot}%{_sharedstatedir}/puzzled/branches
install -d %{buildroot}%{_sharedstatedir}/puzzled/wal

%pre
getent group puzzled >/dev/null || groupadd -r puzzled
getent passwd puzzled >/dev/null || \
    useradd -r -g puzzled -d %{_sharedstatedir}/puzzled -s /sbin/nologin \
    -c "PuzzlePod governance daemon" puzzled
exit 0

%post
%systemd_post puzzled.service
systemd-tmpfiles --create %{_tmpfilesdir}/puzzled.conf 2>/dev/null || :

%preun
%systemd_preun puzzled.service

%postun
%systemd_postun_with_restart puzzled.service

%files
%license LICENSE
%doc README.md
%{_sbindir}/puzzled
%{_unitdir}/puzzled.service
%{_unitdir}/puzzle@.service
%{_unitdir}/puzzle.slice
%{_tmpfilesdir}/puzzled.conf
%dir %{_sysconfdir}/puzzled
%config(noreplace) %attr(0640,root,puzzled) %{_sysconfdir}/puzzled/puzzled.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.lobstertrap.PuzzlePod1.conf
%{_datadir}/dbus-1/interfaces/org.lobstertrap.PuzzlePod1.Manager.xml
%{_mandir}/man8/puzzled.8*
%{_mandir}/man5/puzzled.conf.5*
%dir %attr(0750,root,puzzled) %{_sharedstatedir}/puzzled
%dir %attr(0750,root,puzzled) %{_sharedstatedir}/puzzled/branches
%dir %attr(0750,root,puzzled) %{_sharedstatedir}/puzzled/wal

%changelog
* Mon Mar 09 2026 Francis Chow <fchow@redhat.com> - 0.1.0-1
- Add D-Bus bus policy file (org.lobstertrap.PuzzlePod1.conf)
- Add tmpfiles.d for /run/puzzled runtime state directory
- Add git snapshot macros for COPR pre-release builds
- Add ExclusiveArch, systemd-rpm-macros, shadow-utils dependency

* Sat Mar 07 2026 Francis Chow <fchow@redhat.com> - 0.1.0-0
- Initial package
