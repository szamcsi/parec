Summary: Parallel recursive checksums.
Name: parec
Version: @VERSION@
Release: @AGE@
Source: parec-%{version}.tar.gz
Group: admin
BuildRoot: %{_builddir}/%{name}-%{version}-root
Requires: glibc, openssl
#BuildRequires: gcc, openssl-devel
License: LGPLv2.1
Prefix: /usr

%description
This package contains a library and a simple executable
to calculate multiple checksums of files and directories
at the same time (saving I/O operations) and store them
in extended attributes.

%prep
%setup -q

%build

%install
rm -rf ${RPM_BUILD_ROOT}
make prefix=${RPM_BUILD_ROOT}%{prefix} install

%clean

%files
%defattr(-,root,root)
%{prefix}/bin/checksums
%{prefix}/lib/*.so*
%{prefix}/include/*.h
%doc %{prefix}/share/doc/%{name}

%post

%changelog
