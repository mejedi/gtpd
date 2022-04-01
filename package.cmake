# This script runs at CPack time. As most variables are not available at
# this stage, we have to pass their values explicitly.
# (Expanded via configure_file.)
set(CMAKE_SOURCE_DIR "@CMAKE_SOURCE_DIR@")

# Obtain version (git describe); since we do it at CPack time, the value
# is always up to date. Once a new Git tag is created, it is sufficient
# to invoke the build again. No cleaning is necessary.
execute_process(
    COMMAND "${CMAKE_SOURCE_DIR}/gen_version.sh" OUTPUT_VARIABLE version
)
string(STRIP "${version}" version)

# common settings
# Note: due to CPack bug [1], debuginfo package is NOT generated, UNLESS
# component install is enabled, AND at least two components are defined.
# [1] https://gitlab.kitware.com/cmake/cmake/-/issues/21843
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "mejedi@gmail.com")
unset(CPACK_PACKAGE_DESCRIPTION_SUMMARY) # disable global summary used for every package

# gtpd
set(CPACK_DEBIAN_GTPD_PACKAGE_NAME "gtpd")
set(CPACK_DEBIAN_GTPD_FILE_NAME "DEB-DEFAULT")
set(CPACK_DEBIAN_GTPD_PACKAGE_DEPENDS "libc6, systemd")
set(CPACK_DEBIAN_GTPD_DEBUGINFO_PACKAGE ON)
set(CPACK_DEBIAN_GTPD_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_GTPD_DESCRIPTION "GTPU tunneling daemon")

set(CPACK_DEBIAN_GTPD_PACKAGE_CONTROL_EXTRA
    "${CMAKE_SOURCE_DIR}/debian/postinst"
    "${CMAKE_SOURCE_DIR}/debian/prerm"
    "${CMAKE_SOURCE_DIR}/debian/postrm"
    "${CMAKE_SOURCE_DIR}/debian/conffiles")

# gtpd-dev
set(CPACK_DEBIAN_GTPD_DEV_PACKAGE_NAME "gtpd-dev")
set(CPACK_DEBIAN_GTPD_DEV_FILE_NAME "DEB-DEFAULT")
set(CPACK_DEBIAN_GTPD_DEV_PACKAGE_DEPENDS "gtpd (= ${version})")
set(CPACK_DEBIAN_GTPD_DEV_PACKAGE_SECTION "devel")
set(CPACK_DEBIAN_GTPD_DEV_DESCRIPTION "GTPU tunneling daemon - API headers")

# set CPACK_DEBIAN_PACKAGE_VERSION / CPACK_DEBIAN_PACKAGE_RELEASE
string(FIND "${version}" - last_dash_pos REVERSE)
if(${last_dash_pos} EQUAL -1)
    set(CPACK_DEBIAN_PACKAGE_VERSION "${version}")
else()
    string(SUBSTRING "${version}" 0 ${last_dash_pos} CPACK_DEBIAN_PACKAGE_VERSION)
    string(SUBSTRING "${version}" ${last_dash_pos} -1 CPACK_DEBIAN_PACKAGE_RELEASE)
    string(SUBSTRING "${CPACK_DEBIAN_PACKAGE_RELEASE}" 1 -1 CPACK_DEBIAN_PACKAGE_RELEASE)
endif()
