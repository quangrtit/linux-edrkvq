cmake_minimum_required(VERSION 3.5)
project(SentinelEDR LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXE_LINKER_FLAGS "-static")
# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake)
# Build vendored libbpf
include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install install_uapi_headers
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make bootstrap
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment (like libbpf-bootstrap)
if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
  set(ARCH "x86")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
  set(ARCH "arm")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
  set(ARCH "arm64")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "ppc64le")
  set(ARCH "powerpc")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "mips")
  set(ARCH "mips")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "riscv64")
  set(ARCH "riscv")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "loongarch64")
  set(ARCH "loongarch")
endif()

add_subdirectory(cjson)
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool)
# set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h/include/${ARCH}/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

# Create an executable for each application
file(GLOB apps ${CMAKE_CURRENT_SOURCE_DIR}/src/kernel/*.bpf.c)

set(KERNEL_HEADERS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/kernel")
set(USER_HEADERS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/user") 
set(USER_SPACE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/user/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/user/policy_manager.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/user/utils.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/user/executable_ioc_blocker.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/user/ioc_database.cpp
)

set(MAIN_EXECUTABLE_NAME ${CMAKE_PROJECT_NAME})
foreach(app ${apps})
  get_filename_component(app_stem ${app} NAME_WE)
  file(RELATIVE_PATH app_rel ${CMAKE_CURRENT_SOURCE_DIR} ${app})
  message(STATUS "app_stem = ${app_stem}")
  message(STATUS "app_rel  = ${app_rel}")

  set(BPF_CFLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}/src/kernel")
  bpf_object(${app_stem} ${app_rel})
  add_dependencies(${app_stem}_skel libbpf-build bpftool-build)

  # For SentinelEDR, we will use the name defined by CMAKE_PROJECT_NAME
  # This part of the loop focuses on building BPF objects and their skeletons.
  # The main executable will be defined outside this loop and link to these skeletons.
endforeach()

add_executable(${MAIN_EXECUTABLE_NAME} ${USER_SPACE_SOURCES})
# --- OpenSSL static library setup ---
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

target_link_libraries(${MAIN_EXECUTABLE_NAME} PRIVATE
    ${LIBBPF_LIBRARIES} 
    -l:libelf.a   
    -l:libz.a     
    -l:libzstd.a  
    -lpthread     
    -lrt          
    -ldl 
    OpenSSL::SSL
    OpenSSL::Crypto
    lmdb        
    cjson     
)
# Link the main executable to all generated eBPF skeletons
foreach(app_item ${apps})
  get_filename_component(app_stem_item ${app_item} NAME_WE)
  target_link_libraries(${MAIN_EXECUTABLE_NAME} PRIVATE ${app_stem_item}_skel)
endforeach()
# Set include directories for the main executable
target_include_directories(${MAIN_EXECUTABLE_NAME} PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR} 
    ${CMAKE_CURRENT_BINARY_DIR}/libbpf/bpf
    ${CMAKE_SOURCE_DIR}/cjson
)

# Add dependencies for the main executable to ensure BPF objects are built first
add_dependencies(${MAIN_EXECUTABLE_NAME} libbpf-build bpftool-build)
foreach(app_item ${apps})
    get_filename_component(app_stem_item ${app_item} NAME_WE)
    add_dependencies(${MAIN_EXECUTABLE_NAME} ${app_stem_item}_skel)
endforeach()

set(DEFAULT_POLICY_FILE_PATH "/var/lib/SentinelEDR/self_defense_policy.json" CACHE STRING "Default path to self defense policy JSON file")
target_compile_definitions(SentinelEDR PRIVATE DEFAULT_POLICY_FILE_PATH=\"${DEFAULT_POLICY_FILE_PATH}\")
configure_file("${CMAKE_SOURCE_DIR}/configs/self_defense_policy.json"
               "${CMAKE_BINARY_DIR}/self_defense_policy.json"
               COPYONLY)
configure_file("${CMAKE_SOURCE_DIR}/configs/SentinelEDR.service"
               "${CMAKE_BINARY_DIR}/SentinelEDR.service"
               COPYONLY)
configure_file("${CMAKE_SOURCE_DIR}/install.sh"
               "${CMAKE_BINARY_DIR}/install.sh"
               COPYONLY)
configure_file("${CMAKE_SOURCE_DIR}/uninstall.sh"
               "${CMAKE_BINARY_DIR}/uninstall.sh"
               COPYONLY)
# test file IOC block exe
configure_file("${CMAKE_SOURCE_DIR}/test_environment/tmp/main"
               "${CMAKE_BINARY_DIR}/main_test_block_exe"
               COPYONLY)
file(COPY "${CMAKE_SOURCE_DIR}/configs/IOC_DB"
     DESTINATION "${CMAKE_BINARY_DIR}")
# --- CPack Configuration ---
set_target_properties(${MAIN_EXECUTABLE_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Install the main executable
install(TARGETS ${MAIN_EXECUTABLE_NAME} DESTINATION bin)

# Placeholder for configuration files and other assets
# Define your config files here (e.g., sentinel.conf, rules.json)
set(CONFIG_FILES
    "${CMAKE_SOURCE_DIR}/configs/self_defense_policy.json"
)
# Define the installation destination for config files (e.g., /etc/sentineledr)
set(CONFIG_INSTALL_DIR "/var/lib/${CMAKE_PROJECT_NAME}")
# Install config files if the list is not empty
if(CONFIG_FILES)
    install(FILES ${CONFIG_FILES} DESTINATION ${CONFIG_INSTALL_DIR}
            # Add specific permissions if needed, e.g., PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
endif()
# --- Install systemd service file ---
install(FILES "${CMAKE_SOURCE_DIR}/configs/SentinelEDR.service"
        DESTINATION "/etc/systemd/system/"
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
# Placeholder for systemd service files (if your application runs as a daemon)
# set(SYSTEMD_SERVICE_FILES
#     "${CMAKE_SOURCE_DIR}/configs/SentinelEDR.service"
# )
# if(SYSTEMD_SERVICE_FILES)
#    install(FILES ${SYSTEMD_SERVICE_FILES} DESTINATION "/lib/systemd/system/")
# endif()

set(CPACK_SET_DESTDIR ON)
include(InstallRequiredSystemLibraries)

# CPack package metadata
set(CPACK_PACKAGE_NAME "${CMAKE_PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_CONTACT "vcs@example.com")
set(CPACK_PACKAGE_VENDOR "vcs")
set(CPACK_PACKAGE_DESCRIPTION "SentinelEDR: An Endpoint Detection and Response Agent for Linux.")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://vcs.com")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-linux-${CMAKE_SYSTEM_PROCESSOR}")
# --- Ubuntu (DEB) specific CPack settings ---
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
set(CPACK_DEBIAN_COMPRESSION_TYPE "xz")
# set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6")

include(CPack)