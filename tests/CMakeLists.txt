# ECMP Governor test suite.
#
# Every test is registered with CTest plainly: no timeouts, no retries, no
# parallel-resource assumptions that could hide a hang or a race.

set(ECMP_TEST_SUPPORT ${CMAKE_CURRENT_SOURCE_DIR}/support/test_main.cpp)

function(ecmp_add_test name)
  add_executable(${name} ${ECMP_TEST_SUPPORT} ${ARGN})
  target_link_libraries(${name} PRIVATE ecmp_governor)
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/support)
  target_compile_options(${name} PRIVATE ${ECMP_WARNING_FLAGS})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

ecmp_add_test(ecmp_test_core test_core.cpp)
ecmp_add_test(ecmp_test_governor test_governor.cpp)
ecmp_add_test(ecmp_test_persistence test_persistence.cpp)
ecmp_add_test(ecmp_test_protocol test_protocol.cpp)
ecmp_add_test(ecmp_test_property test_property.cpp)
ecmp_add_test(ecmp_test_adversarial test_adversarial.cpp)
ecmp_add_test(ecmp_test_scale test_scale.cpp)

if(ECMP_BUILD_APPS)
  add_executable(ecmp_test_distributed ${ECMP_TEST_SUPPORT} test_distributed.cpp)
  target_link_libraries(ecmp_test_distributed PRIVATE ecmp_governor)
  target_include_directories(ecmp_test_distributed PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/support)
  target_compile_options(ecmp_test_distributed PRIVATE ${ECMP_WARNING_FLAGS})
  target_compile_definitions(ecmp_test_distributed PRIVATE
    ECMP_COORDINATOR_EXECUTABLE="$<TARGET_FILE:ecmp_coordinator>"
    ECMP_WORKER_EXECUTABLE="$<TARGET_FILE:ecmp_worker>"
    ECMP_CLI_EXECUTABLE="$<TARGET_FILE:ecmp_cli>")
  add_test(NAME ecmp_test_distributed COMMAND ecmp_test_distributed)
endif()
