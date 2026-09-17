# ECMP Governor benchmarks.  These are deliberately not registered as tests: they
# measure completed work on this machine and this build, and their numbers are
# observations rather than assertions.

add_executable(ecmp_benchmark ecmp_benchmark.cpp)
target_link_libraries(ecmp_benchmark PRIVATE ecmp_governor)
target_compile_options(ecmp_benchmark PRIVATE ${ECMP_WARNING_FLAGS})
