Name:       system-resource
Summary:    System Resource Daemon
Version:    0.0.1
Release:    1
Group:      System/Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    resourced.service

%define powertop_state OFF
%define exclude_list_opt_full_path /opt/usr/etc/_exclude_list_file_name_


BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(vconf-internal-keys)
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(x11)
BuildRequires:  pkgconfig(ecore-x)
BuildRequires:  pkgconfig(utilX)
BuildRequires:  pkgconfig(ecore-input)
BuildRequires:  pkgconfig(ecore-file)
BuildRequires:  pkgconfig(edbus)

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
System Resource Daemon to manage memory and process state

%package devel
Summary:  System Resource Information (Development)
Group:    System/Development
Requires: %{name} = %{version}-%{release}

%description devel
Development package for Resourced Daemon
to manage memory and process state

%if %{?powertop_state} == ON
%package powertop-wrapper
Summary: Powertop-wrapper libray
Group:   System/Libraries

%description powertop-wrapper
Powertop control library
%endif

%prep
%setup -q

%build
MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
MINORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $2}'`
PATCHVER=`echo %{version} | awk 'BEGIN {FS="."}{print $3}'`
echo "\
/* That file was generated automaticaly. Don't edit it */
#define MINOR_VERSION ${MINORVER}
#define MAJOR_VERSION ${MAJORVER}
#define PATCH_VERSION ${PATCHVER}" > src/common/version.h

%if 0%{?tizen_build_binary_release_type_eng}
	CFLAGS+=" -DTIZEN_ENGINEER_MODE"
%endif

cmake . -DCMAKE_INSTALL_PREFIX=/usr -DFULLVER=%{version} -DMAJORVER=${MAJORVER} -DCMAKE_BUILD_TYPE=Release \
	-DEXCLUDE_LIST_OPT_FULL_PATH=%{exclude_list_opt_full_path} \
	-DPOWERTOP_MODULE=%{powertop_state}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp -f LICENSE %{buildroot}/usr/share/license/%{name}

%if %{?powertop_state} == ON
cp -f LICENSE %{buildroot}/usr/share/license/%{name}-powertop-wrapper
%endif

%make_install

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
install -m 0644 %SOURCE1 %{buildroot}%{_libdir}/systemd/system/resourced.service
ln -s ../resourced.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/resourced.service

#powertop-wrapper part
%if %{?powertop_state} == ON
mkdir -p %{buildroot}/usr/share/powertop-wrapper/
cp -p %_builddir/%name-%version/src/powertop-wrapper/header.html %{buildroot}/usr/share/powertop-wrapper
%endif

%post
/sbin/ldconfig

mkdir -p /opt/usr/etc

if [ "$1" = "2" ]; then # upgrade begins
	systemctl start resourced.service
fi

%postun
/sbin/ldconfig

%if %{?powertop_state} == ON
%post powertop-wrapper -p /sbin/ldconfig
%postun powertop-wrapper -p /sbin/ldconfig
%endif

%files
%manifest resourced.manifest
%{_libdir}/libproc-stat.so.*
/usr/share/license/%{name}
%attr(-,root, root) %{_bindir}/resourced
%config %{_sysconfdir}/dbus-1/system.d/resourced.conf
%{_libdir}/systemd/system/resourced.service
%{_libdir}/systemd/system/multi-user.target.wants/resourced.service
%config /etc/resourced/memory.conf

%if %{?powertop_state} == ON
%files powertop-wrapper
%manifest powertop-wrapper.manifest
%{_libdir}/libpowertop-wrapper.so.*
/usr/share/powertop-wrapper/header.html
/usr/share/license/%{name}-powertop-wrapper
%endif

%files devel
%{_libdir}/pkgconfig/*.pc
%{_includedir}/system/proc_stat.h
%{_libdir}/libproc-stat.so
%{_includedir}/system/resourced.h

%if %{?powertop_state} == ON
#powertop-wrapper part
%{_includedir}/system/powertop-dapi.h
%{_libdir}/libpowertop-wrapper.so
%endif
