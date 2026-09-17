# ECMP Governor examples.  Every example is registered with CTest so that a
# release validation actually executes it.

add_executable(ecmp_example_api api_examples.cpp)
target_link_libraries(ecmp_example_api PRIVATE ecmp_governor)
target_compile_options(ecmp_example_api PRIVATE ${ECMP_WARNING_FLAGS})
add_test(NAME ecmp_example_api COMMAND ecmp_example_api)

if(ECMP_BUILD_APPS)
  add_executable(ecmp_example_distributed distributed_example.cpp)
  target_link_libraries(ecmp_example_distributed PRIVATE ecmp_governor)
  target_compile_options(ecmp_example_distributed PRIVATE ${ECMP_WARNING_FLAGS})
  target_compile_definitions(ecmp_example_distributed PRIVATE
    ECMP_COORDINATOR_EXECUTABLE="$<TARGET_FILE:ecmp_coordinator>"
    ECMP_WORKER_EXECUTABLE="$<TARGET_FILE:ecmp_worker>")
  add_test(NAME ecmp_example_distributed COMMAND ecmp_example_distributed)
endif()
