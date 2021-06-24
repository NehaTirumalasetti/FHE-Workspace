cmake_minimum_required(VERSION 3.10)

project(bin_comp_test VERSION 0.0.1 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS "-Werror -fopenmp -Wfatal-errors")

## Rely on the Environment variable to dictate which version of helib to use
set(HELIB_VERSION ${HELIB_CMAKE_LISTS_VERSON})

find_package(helib ${HELIB_VERSION} REQUIRED)
find_package(Boost 1.72.0 EXACT REQUIRED COMPONENTS filesystem system thread)
find_package(HDF5 REQUIRED COMPONENTS CXX)
include_directories(${HDF5_INCLUDE_DIR})

add_executable(bin_comp_test  bin_comp_test.cpp)
target_link_libraries(bin_comp_test mlhelib helib ${HDF5_LIBRARIES} ${Boost_LIBRARIES})