cmake_minimum_required(VERSION 3.25)

# Independent downstream consumer of the installed ECMP Governor package.
#
# This project is deliberately separate from the ECMP Governor build: it must find
# the package through find_package(ECMPGovernor CONFIG REQUIRED), compile against
# the installed headers only and link the exported imported target.  Nothing from
# the ECMP Governor source tree is on its include path.

project(EcmpGovernorConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(ECMPGovernor CONFIG REQUIRED)

if(NOT TARGET SummonSoftwareLabs::ECMPGovernor)
  message(FATAL_ERROR
    "The ECMPGovernor package did not export the documented imported target "
    "SummonSoftwareLabs::ECMPGovernor")
endif()

message(STATUS "ECMPGovernor package version: ${ECMPGovernor_VERSION}")
message(STATUS "ECMPGovernor imported target: SummonSoftwareLabs::ECMPGovernor")

add_executable(ecmp_consumer consumer_main.cpp)
target_link_libraries(ecmp_consumer PRIVATE SummonSoftwareLabs::ECMPGovernor)
