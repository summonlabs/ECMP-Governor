cmake_minimum_required(VERSION 3.25)

project(ECMPGovernor
  VERSION 1.0.0
  DESCRIPTION "Deterministic equal-cost multipath membership, eligibility and rebalance governance runtime"
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(ECMP_BUILD_TESTS "Build the ECMP Governor test suite" ON)
option(ECMP_BUILD_EXAMPLES "Build the ECMP Governor examples" ON)
option(ECMP_BUILD_BENCHMARKS "Build the ECMP Governor benchmarks" ON)
option(ECMP_BUILD_APPS "Build the coordinator, worker and CLI applications" ON)
option(ECMP_ENABLE_ASAN "Build with MSVC AddressSanitizer" OFF)
option(ECMP_ENABLE_ANALYZE "Build with MSVC /analyze" OFF)
option(ECMP_WARNINGS_AS_ERRORS "Treat first-party warnings as errors" ON)

set(ECMP_WARNING_FLAGS /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
if(ECMP_WARNINGS_AS_ERRORS)
  list(APPEND ECMP_WARNING_FLAGS /WX)
endif()
if(ECMP_ENABLE_ANALYZE)
  list(APPEND ECMP_WARNING_FLAGS /analyze)
endif()

if(ECMP_ENABLE_ASAN)
  # MSVC AddressSanitizer requires the dynamic CRT and the sanitizer runtime.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  add_compile_options(/fsanitize=address)
  add_link_options(/fsanitize=address)
  message(STATUS "ECMP Governor: AddressSanitizer requested (MSVC /fsanitize=address)")
endif()

add_library(ecmp_governor STATIC
  src/assignment.cpp
  src/authority.cpp
  src/bytes.cpp
  src/client.cpp
  src/cost.cpp
  src/digest.cpp
  src/group.cpp
  src/governor_core.cpp
  src/governor_mutate.cpp
  src/governor_query.cpp
  src/lifecycle.cpp
  src/limits.cpp
  src/outcome.cpp
  src/process.cpp
  src/protocol.cpp
  src/server.cpp
  src/store.cpp
  src/synthetic.cpp
  src/transport.cpp
  src/version.cpp)
add_library(SummonSoftwareLabs::ECMPGovernor ALIAS ecmp_governor)
set_target_properties(ecmp_governor PROPERTIES
  EXPORT_NAME ECMPGovernor
  POSITION_INDEPENDENT_CODE ON)
target_include_directories(ecmp_governor PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_options(ecmp_governor PRIVATE ${ECMP_WARNING_FLAGS})
target_compile_features(ecmp_governor PUBLIC cxx_std_20)

if(WIN32)
  target_link_libraries(ecmp_governor PUBLIC ws2_32)
else()
  message(FATAL_ERROR
    "ECMP Governor 1.0.0 targets Windows: the loopback transport, the coordinator "
    "service, the worker client and the real-process proofs are implemented against "
    "Win32/Winsock. The control-plane library itself is portable C++20, but 1.0.0 "
    "does not claim a validated non-Windows build.")
endif()

# --- applications -----------------------------------------------------------
if(ECMP_BUILD_APPS)
  add_library(ecmp_app_support STATIC app/support.cpp)
  target_include_directories(ecmp_app_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/app)
  target_link_libraries(ecmp_app_support PUBLIC ecmp_governor)
  target_compile_options(ecmp_app_support PRIVATE ${ECMP_WARNING_FLAGS})

  add_executable(ecmp_coordinator app/coordinator_main.cpp)
  target_link_libraries(ecmp_coordinator PRIVATE ecmp_app_support)
  target_compile_options(ecmp_coordinator PRIVATE ${ECMP_WARNING_FLAGS})

  add_executable(ecmp_worker app/worker_main.cpp)
  target_link_libraries(ecmp_worker PRIVATE ecmp_app_support)
  target_compile_options(ecmp_worker PRIVATE ${ECMP_WARNING_FLAGS})

  add_executable(ecmp_cli app/cli_main.cpp)
  target_link_libraries(ecmp_cli PRIVATE ecmp_app_support)
  target_compile_options(ecmp_cli PRIVATE ${ECMP_WARNING_FLAGS})
endif()

# --- tests, examples, benchmarks -------------------------------------------
if(ECMP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
if(ECMP_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(ECMP_BUILD_BENCHMARKS)
  add_subdirectory(bench)
endif()

# --- install and export -----------------------------------------------------
install(TARGETS ecmp_governor
  EXPORT ECMPGovernorTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(ECMP_BUILD_APPS)
  install(TARGETS ecmp_cli ecmp_coordinator ecmp_worker
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY include/ecmp
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.hpp")

install(EXPORT ECMPGovernorTargets
  FILE ECMPGovernorTargets.cmake
  NAMESPACE SummonSoftwareLabs::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ECMPGovernor)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ECMPGovernorConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/ECMPGovernorConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ECMPGovernor)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/ECMPGovernorConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/ECMPGovernorConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/ECMPGovernorConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ECMPGovernor)

install(FILES LICENSE README.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/ECMPGovernor)
