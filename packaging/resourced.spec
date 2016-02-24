Name:       resourced
Summary:    Resource management daemon
Version:    0.2.86
Release:    0
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    resourced.service
Source2:    resourced-cpucgroup.service

%define powertop_state OFF
%define cpu_module ON
%define vip_agent_module ON
%define timer_slack OFF

%define heart_module ON

%define memory_module ON
%define block_module ON
%define wearable_noti OFF
%define network_state OFF
%define memory_eng ON

%if "%{?tizen_profile_name}" == "mobile"
	# %if ("%{_repository}" == "target-Z130H") || %if ("%{_repository}" == "target-Z300H")
	# %if ("%{_repository}" == "target-Z130H")
	%if "%{_repository}" == "target-Z130H" || "%{_repository}" == "target-TM1"
		%define swap_module ON
		%define memory_vmpressure ON
	%else
		%define swap_module OFF
		%define memory_vmpressure OFF
	%endif
        %define freezer_module ON
	%define network_state OFF
	%define tethering_feature OFF
	%define wearable_noti OFF
	%define telephony_feature OFF
%endif

%if "%{?tizen_profile_name}" == "wearable"
        %define freezer_module ON
	%define swap_module ON
	%define memory_vmpressure ON
	%define network_state OFF
	%define tethering_feature OFF
	%define wearable_noti ON
	%define telephony_feature OFF
%endif

%if "%{?tizen_profile_name}" == "tv"
	%define freezer_module OFF
	%define swap_module OFF
	%define memory_vmpressure ON
	%define network_state OFF
	%define tethering_feature OFF
	%define wearable_noti OFF
	%define telephony_feature OFF
%endif

%define exclude_list_file_name resourced_proc_exclude.ini
%define exclude_list_full_path /usr/etc/%{exclude_list_file_name}
%define exclude_list_opt_full_path /opt/usr/etc/%{exclude_list_file_name}
%define database_full_path /opt/usr/dbspace/.resourced-datausage.db

%define logging_db_full_path /opt/usr/dbspace/.resourced-logging.db
%define logging_storage_db_full_path /opt/usr/dbspace/.resourced-logging-storage.db

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
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(leveldb)
BuildRequires:  pkgconfig(eventsystem)
#only for data types
BuildRequires:  pkgconfig(tapi)

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%if %{?heart_module} == ON
BuildRequires:  pkgconfig(libsystemd-journal)
%endif

%description
Resourced daemon

%package resourced
Summary: Resource Daemon
Group:   System/Libraries

%description resourced
Resource management daemon for memory management and process management (vip processes)

%package -n libresourced
Summary: Resource Daemon Library
Group:   System/Libraries
Requires:   %{name} = %{version}-%{release}

%description -n libresourced
Library for resourced (Resource Management Daemon)

%package -n libresourced-devel
Summary: Resource Daemon Library (Development)
Group:   System/Libraries
Requires:   libresourced  = %{version}-%{release}

%description -n libresourced-devel
Library (development) for resourced (Resource Management Daemon)

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

%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif

%cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} \
	 -DFULLVER=%{version} \
	 -DMAJORVER=${MAJORVER} \
	 -DCMAKE_BUILD_TYPE=Release \
	 -DEXCLUDE_LIST_FILE_NAME=%{exclude_list_file_name} \
	 -DEXCLUDE_LIST_FULL_PATH=%{exclude_list_full_path} \
	 -DDATABASE_FULL_PATH=%{database_full_path} \
	 -DEXCLUDE_LIST_OPT_FULL_PATH=%{exclude_list_opt_full_path} \
	 -DNETWORK_MODULE=%{network_state} \
	 -DSWAP_MODULE=%{swap_module} \
	 -DPOWERTOP_MODULE=%{powertop_state} \
	 -DFREEZER_MODULE=%{freezer_module} \
	 -DCPU_MODULE=%{cpu_module} \
	 -DMEMORY_ENG=%{memory_eng} \
	 -DVIP_AGENT=%{vip_agent_module} \
	 -DTELEPHONY_FEATURE=%{telephony_feature} \
	 -DTIMER_SLACK=%{timer_slack} \
	 -DHEART_MODULE=%{heart_module} \
	 -DDATAUSAGE_TYPE=NFACCT \
	 -DMEMORY_MODULE=%{memory_module} \
	 -DMEMORY_VMPRESSURE=%{memory_vmpressure} \
	 -DWEARABLE_NOTI=%{wearable_noti} \
	 -DBLOCK_MODULE=%{block_module}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp -f LICENSE %{buildroot}/usr/share/license/%{name}
cp -f LICENSE %{buildroot}/usr/share/license/libresourced

%make_install
%if %{?heart_module} == ON
	mkdir -p %{buildroot}/opt/usr/data/heart
	mkdir -p %{buildroot}/opt/usr/dbspace
	sqlite3 %{buildroot}%{logging_db_full_path}
	sqlite3 --line %{buildroot}%{logging_storage_db_full_path} 'PRAGMA journal_mode = WAL'
	touch %{buildroot}%{logging_storage_db_full_path}-shm
	touch %{buildroot}%{logging_storage_db_full_path}-wal
%endif

%if %{?network_state} == ON
	mkdir -p %{buildroot}/opt/usr/dbspace
	sqlite3 %{buildroot}%{database_full_path} < %{buildroot}/usr/share/traffic_db.sql
	rm %{buildroot}/usr/share/traffic_db.sql
%endif

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants

install -m 0644 %SOURCE1 %{buildroot}%{_libdir}/systemd/system/resourced.service
ln -s ../resourced.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/resourced.service

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

%pre resourced
if [ "$1" = "2" ]; then # upgrade begins
	systemctl stop resourced.service
fi

%post -p /sbin/ldconfig

%post resourced

init_vconf()
{
	vconftool set -t bool db/private/resourced/wifi_statistics 1 -i -f -s tizen::vconf::platform::rw
	vconftool set -t bool db/private/resourced/datacall 1 -i -f -s tizen::vconf::platform::rw
	vconftool set -t bool db/private/resourced/datacall_logging 1 -i -f -s tizen::vconf::platform::rw
	vconftool set -t string db/private/resourced/new_limit "" -u 5000 -f -s tizen::vconf::platform::rw
	vconftool set -t string db/private/resourced/delete_limit "" -u 5000 -f -s tizen::vconf::platform::rw
	vconftool set -t int db/private/resourced/network_db_entries 0 -i -f -s tizen::vconf::platform::rw
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

%files -n resourced
/usr/share/license/%{name}
/etc/smack/accesses2.d/resourced.rule
%attr(-,root, root) %{_bindir}/resourced
%if %{?network_state} == ON
	%config(noreplace) %attr(660,root,app) %{database_full_path}
	%config(noreplace) %attr(660,root,app) %{database_full_path}-journal
	/usr/bin/datausagetool
	%config /etc/resourced/network.conf
	/etc/opt/upgrade/500.resourced-datausage.patch.sh
	%attr(700,root,root) /etc/opt/upgrade/500.resourced-datausage.patch.sh
	%manifest resourced.manifest
	%{_bindir}/net-cls-release
%else
%manifest resourced_nodb.manifest
%endif
%config %{_sysconfdir}/dbus-1/system.d/resourced.conf
%{_libdir}/systemd/system/resourced.service
%{_libdir}/systemd/system/multi-user.target.wants/resourced.service
%config /etc/resourced/memory.conf
%config /etc/resourced/proc.conf
%if %{?cpu_module} == ON
%config /etc/resourced/cpu.conf
%else
%{_bindir}/resourced-cpucgroup.sh
%{_libdir}/systemd/system/resourced-cpucgroup.service
%{_libdir}/systemd/system/graphical.target.wants/resourced-cpucgroup.service
%endif
%if %{?swap_module} == ON
%config /etc/resourced/swap.conf
%endif
%if %{?vip_agent_module} == ON
%config /etc/resourced/vip-process.conf
%attr(-,root, root) %{_bindir}/vip-release-agent
%endif
%if %{?timer_slack} == ON
%config /etc/resourced/timer-slack.conf
%endif
%if %{?block_module} == ON
%config /etc/resourced/block.conf
%endif
%if %{?freezer_module} == ON
%config /etc/resourced/freezer.conf
%endif
%{exclude_list_full_path}
%if %{?powertop_state} == ON
/usr/share/powertop-wrapper/header.html
%endif
%if %{?heart_module} == ON
%config /etc/resourced/heart.conf
%attr(700, root, root) /opt/etc/dump.d/module.d/dump_heart_data.sh
%attr(700, app, app) %{logging_storage_db_full_path}
%attr(700, app, app) %{logging_storage_db_full_path}-shm
%attr(700, app, app) %{logging_storage_db_full_path}-wal
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
%if %{?network_state} == ON
%{_includedir}/system/data_usage.h
%endif
%{_libdir}/libresourced.so
#powertop-wrapper part
%if %{?powertop_state} == ON
%{_includedir}/system/powertop-dapi.h
%{_libdir}/libpowertop-wrapper.so
%endif
