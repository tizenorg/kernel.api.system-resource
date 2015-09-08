Name:       system-resource
Summary:    System Resource Information
Version:    0.2.86
Release:    0
VCS:        magnolia/kernel/api/system-resource#submit/master/20131010.041510-19-gcf6121a4bcce9c122d4ea05fa9974ec7bac227d8
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    resourced.service
Source2:    resourced-zram.service
Source5:    resourced_swapoff.service
Source6:    resourced-cpucgroup.service
Source8:    resourced-logging.service

%define powertop_state OFF
%define cpu_module ON
%define vip_agent_module ON
%define timer_slack ON
%define logging_module OFF
%define logging_memory OFF
%define logging_cpu OFF
%define memory_module ON
%define memory_cgroup OFF

%if "%{?tizen_profile_name}" == "mobile"
	%define swap_module OFF
	%define network_state OFF
	%define network_service OFF
	%define telephony_feature OFF
	%define tethering_feature OFF

%endif

%if "%{?tizen_profile_name}" == "wearable"
	%define swap_module OFF
	%define network_state OFF
	%define network_service OFF
	%define telephony_feature OFF

%endif

%if 0%{?tizen_build_binary_release_type_eng}
	%define memory_eng ON
%else
	%define memory_eng OFF
%endif

%define exclude_list_file_name resourced_proc_exclude.ini
%define exclude_list_full_path /usr/etc/%{exclude_list_file_name}
%define exclude_list_opt_full_path /opt/usr/etc/%{exclude_list_file_name}
%define database_full_path /opt/usr/dbspace/.resourced-datausage.db

BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(vconf-internal-keys)
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(ecore-file)
BuildRequires:  pkgconfig(eina)
BuildRequires:  pkgconfig(edbus)
BuildRequires:  pkgconfig(capi-network-connection)
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(journal)

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%if %{?logging_module} == ON
BuildRequires:  pkgconfig(libsystemd-journal)
%endif

%description

%package resourced
Summary: Resource Daemon
Group:   System/Libraries
Requires:   %{name} = %{version}-%{release}

%description resourced
Resource Daemon

%package -n libresourced
Summary: Resource Daemon Library
Group:   System/Libraries
Requires:   %{name} = %{version}-%{release}

%description -n libresourced
Resource Daemon Library

%package -n libresourced-devel
Summary: Resource Daemon Library (Development)
Group:   System/Libraries
Requires:   %{name} = %{version}-%{release}

%description -n libresourced-devel
Resource Daemon Library (Development)

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

export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

cmake . -DCMAKE_INSTALL_PREFIX=/usr -DFULLVER=%{version} -DMAJORVER=${MAJORVER} -DCMAKE_BUILD_TYPE=Release \
	-DEXCLUDE_LIST_FILE_NAME=%{exclude_list_file_name} \
	-DEXCLUDE_LIST_FULL_PATH=%{exclude_list_full_path} -DDATABASE_FULL_PATH=%{database_full_path} \
	-DEXCLUDE_LIST_OPT_FULL_PATH=%{exclude_list_opt_full_path} -DNETWORK_MODULE=%{network_state} -DNETWORK_SERVICE=%{network_service} \
	-DSWAP_MODULE=%{swap_module} -DPOWERTOP_MODULE=%{powertop_state} -DCPU_MODULE=%{cpu_module}\
	-DMEMORY_ENG=%{memory_eng} -DVIP_AGENT=%{vip_agent_module} -DTELEPHONY_FEATURE=%{telephony_feature} \
	-DTIMER_SLACK=%{timer_slack} -DLOGGING_MODULE=%{logging_module} -DLOGGING_MEMORY=%{logging_memory} \
	-DLOGGING_CPU=%{logging_cpu} -DDATAUSAGE_TYPE=NFACCT -DMEMORY_MODULE=%{memory_module} -DMEMORY_CGROUP=%{memory_cgroup}  \
	-DTETHERING_FEATURE=%{tethering_feature}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp -f LICENSE %{buildroot}/usr/share/license/%{name}
cp -f LICENSE %{buildroot}/usr/share/license/libresourced

%make_install

%if %{?network_state} == ON
	mkdir -p %{buildroot}/opt/usr/dbspace
	sqlite3 %{buildroot}%{database_full_path} < %{buildroot}/usr/share/traffic_db.sql
	rm %{buildroot}/usr/share/traffic_db.sql
%endif

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
%if %{?swap_module} == ON
install -m 0644 %SOURCE1 %{buildroot}%{_libdir}/systemd/system/resourced.service
ln -s ../resourced.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/resourced.service

mkdir -p %{buildroot}%{_libdir}/systemd/system/graphical.target.wants
install -m 0644 %SOURCE2 %{buildroot}%{_libdir}/systemd/system/resourced-zram.service
ln -s ../resourced-zram.service %{buildroot}%{_libdir}/systemd/system/graphical.target.wants/resourced-zram.service
%else
install -m 0644 %SOURCE5 %{buildroot}%{_libdir}/systemd/system/resourced.service
ln -s ../resourced.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/resourced.service
%endif

%if %{?cpu_module} == OFF
mkdir -p %{buildroot}%{_libdir}/systemd/system/graphical.target.wants
install -m 0644 %SOURCE6 %{buildroot}%{_libdir}/systemd/system/resourced-cpucgroup.service
ln -s ../resourced-cpucgroup.service %{buildroot}%{_libdir}/systemd/system/graphical.target.wants/resourced-cpucgroup.service
%endif

#powertop-wrapper part
%if %{?powertop_state} == ON
mkdir -p %{buildroot}/usr/share/powertop-wrapper/
cp -p %_builddir/%name-%version/src/powertop-wrapper/header.html %{buildroot}/usr/share/powertop-wrapper
%endif

%if %{?logging_module} == ON
#logging service file
mkdir -p %{buildroot}%{_libdir}/systemd/system/graphical.target.wants
install -m 0644 %SOURCE8 %{buildroot}%{_libdir}/systemd/system/resourced-logging.service
ln -s ../resourced-logging.service %{buildroot}%{_libdir}/systemd/system/graphical.target.wants/resourced-logging.service
%endif

%pre resourced
if [ "$1" = "2" ]; then # upgrade begins
	systemctl stop resourced.service
fi

%post -p /sbin/ldconfig

%post resourced

init_vconf()
{
	vconftool set -t bool db/private/resourced/wifi_statistics 1 -i -f -s resourced
	vconftool set -t bool db/private/resourced/datacall 1 -i -f -s resourced
	vconftool set -t bool db/private/resourced/datacall_logging 1 -i -f -s resourced
	vconftool set -t int db/private/resourced/datausage_timer 60 -i -f -s resourced
	vconftool set -t string db/private/resourced/new_limit "" -u 5000 -f -s resourced
	vconftool set -t string db/private/resourced/delete_limit "" -u 5000 -f -s resourced
}

%if %{?network_state} == ON
	init_vconf
%endif
#install init.d script
mkdir -p /opt/usr/etc
#make empty dynamic exclude list for first installation
touch %{exclude_list_opt_full_path}

if [ "$1" = "2" ]; then # upgrade begins
	systemctl start resourced.service
fi

%postun -p /sbin/ldconfig

%files
/usr/share/license/%{name}
%attr(-,root, root) %{_bindir}/resourced
%if %{?network_state} == ON
	%config(noreplace) %attr(660,root,app) %{database_full_path}
	%config(noreplace) %attr(660,root,app) %{database_full_path}-journal
	/usr/bin/datausagetool
	%manifest resourced.manifest
%else
%manifest resourced_nodb.manifest
%endif
%config %{_sysconfdir}/dbus-1/system.d/resourced.conf
%{_libdir}/systemd/system/resourced.service
%{_libdir}/systemd/system/multi-user.target.wants/resourced.service
/etc/resourced/memory.conf
%if %{?cpu_module} == ON
/etc/resourced/cpu.conf
%else
%{_bindir}/resourced-cpucgroup.sh
%{_libdir}/systemd/system/resourced-cpucgroup.service
%{_libdir}/systemd/system/graphical.target.wants/resourced-cpucgroup.service
%endif
%if %{?swap_module} == ON
%{_libdir}/systemd/system/resourced-zram.service
%{_libdir}/systemd/system/graphical.target.wants/resourced-zram.service
%{_bindir}/resourced-zram.sh
%endif
%if %{?logging_module} == ON
%{_libdir}/systemd/system/resourced-logging.service
%{_libdir}/systemd/system/graphical.target.wants/resourced-logging.service
%endif
%if %{?vip_agent_module} == ON
/etc/resourced/vip-process.conf
%attr(-,root, root) %{_bindir}/vip-release-agent
%endif
%if %{?timer_slack} == ON
/etc/resourced/timer-slack.conf
%endif
%{exclude_list_full_path}
%if %{?powertop_state} == ON
/usr/share/powertop-wrapper/header.html
%endif

#memps
%attr(-,root, root) %{_bindir}/memps

%files -n libresourced
%manifest libresourced.manifest
%defattr(-,root,root,-)
/usr/share/license/libresourced
#proc-stat part
%{_libdir}/libproc-stat.so.*
#network part
%{_libdir}/libresourced.so.*
%if %{?network_state} == ON
%{_libdir}/librd-network.so.*
%endif
#powertop-wrapper part
%if %{?powertop_state} == ON
%{_libdir}/libpowertop-wrapper.so.*
%endif

%files -n libresourced-devel
%defattr(-,root,root,-)
%{_libdir}/pkgconfig/*.pc
%{_includedir}/system/resourced.h
#proc-stat part
%{_includedir}/system/proc_stat.h
%{_libdir}/libproc-stat.so
#network part
%{_libdir}/libresourced.so
%if %{?network_state} != OFF
%{_includedir}/system/data_usage.h
%{_includedir}/system/rd-network.h
%{_libdir}/librd-network.so
/etc/resourced/network.conf
%endif
#powertop-wrapper part
%if %{?powertop_state} == ON
%{_includedir}/system/powertop-dapi.h
%{_libdir}/libpowertop-wrapper.so
%endif
