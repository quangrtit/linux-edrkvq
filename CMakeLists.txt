cmake_minimum_required(VERSION 3.16)
project(SentinelEDR C)
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -target bpf -m64")
# Tell cmake where to find BpfObject module
# list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../tools/cmake)
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
# file(COPY ${KERNEL_HEADERS_DIR}/ 
#      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
#      FILES_MATCHING PATTERN "*.h") 
# file(COPY ${USER_HEADERS_DIR}/ 
#      DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
#      FILES_MATCHING PATTERN "*.h") 

set(USER_SPACE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/user/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/user/policy_manager.c
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
# target_link_libraries(${MAIN_EXECUTABLE_NAME} PRIVATE ${LIBBPF_LIBRARIES})
target_link_libraries(${MAIN_EXECUTABLE_NAME} PRIVATE
    ${LIBBPF_LIBRARIES} 
    ${USER_HEADERS_DIR}
    -l:libelf.a   
    -l:libz.a     
    -l:libzstd.a  
    -lpthread     
    -lrt          
    -ldl 
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

# add_subdirectory(cjson)
# target_link_libraries(${MAIN_EXECUTABLE_NAME} PRIVATE cjson)
# target_include_directories(${MAIN_EXECUTABLE_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/cjson)



# --- CPack Configuration ---
set_target_properties(${MAIN_EXECUTABLE_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Install the main executable
install(TARGETS ${MAIN_EXECUTABLE_NAME} DESTINATION bin)

# Placeholder for configuration files and other assets
# Define your config files here (e.g., sentinel.conf, rules.json)
set(CONFIG_FILES
    # "${CMAKE_CURRENT_SOURCE_DIR}/configs/sentinel.conf"
    # "${CMAKE_CURRENT_SOURCE_DIR}/certs/ca.crt"
)
# Define the installation destination for config files (e.g., /etc/sentineledr)
set(CONFIG_INSTALL_DIR "/etc/${CMAKE_PROJECT_NAME}")
# Install config files if the list is not empty
if(CONFIG_FILES)
    install(FILES ${CONFIG_FILES} DESTINATION ${CONFIG_INSTALL_DIR}
            # Add specific permissions if needed, e.g., PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    )
endif()

# Placeholder for systemd service files (if your application runs as a daemon)
# set(SYSTEMD_SERVICE_FILES
#     "${CMAKE_CURRENT_SOURCE_DIR}/systemd/sentinel.service"
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