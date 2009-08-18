Summary: Parallel recursive checksums.
Name: parec
Version: @VERSION@
Release: @AGE@
Source: parec-%{version}.tar.gz
Group: admin
BuildRoot: %{_builddir}/%{name}-%{version}-root
Requires: glibc, openssl, python
BuildRequires: gcc, openssl-devel, attr, python-devel >= 2.3, docbook-style-xsl, docbook-utils, libxslt, doxygen
License: LGPLv2.1
Prefix: /usr

%description
This package contains a library and a simple executable
to calculate multiple checksums of files and directories
at the same time (saving I/O operations) and store them
in extended attributes.

%package devel
Summary: Parallel Recursive Checksums development package
Group: admin
Requires: %{name} >= %{version}
%description devel
This package contains the header files and documentation
for development in C.

%package -n python-parec
Summary: Parallel Recursive Checksums Python binding
Group: admin
Requires: %{name} >= %{version}
%description -n python-parec
This package contains the Python binding for the library.

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
%{prefix}/lib/libparec.so.*
%doc %{prefix}/share/doc/%{name}/README
%doc %{prefix}/share/man/man1

%files devel
%{prefix}/lib/libparec.so
%{prefix}/include/parec*.h
%doc %{prefix}/share/doc/%{name}/html
%doc %{prefix}/share/doc/%{name}/examples
%doc %{prefix}/share/man/man3

%files -n python-parec
%{prefix}/lib/python*/site-packages/parecmodule.so

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%changelog
* Tue Aug 18 2009 Frohner Ákos <akos@frohner.hu> 1.0.0-1

- First public release.
- Added Python interface.
- Added a manual pages and HTML documentation.
- Split Debian packages and RPMs: parec, parec-dev(el), python-parec

* Fri Aug  7 2009 Frohner Ákos <akos@frohner.hu> 0.1.0-1

- Initial release.

