cmake_minimum_required(VERSION 3.10)
project(cpp-isal-crypto CXX)

include(GoogleTest)
find_package(Threads)
find_package(PkgConfig REQUIRED)

enable_testing()

set(CMAKE_CXX_STANDARD 17)

option(ASAN "Enable ASAN (address sanitizer)" OFF)
option(TSAN "Enable TSAN (thread sanitizer)" OFF)
option(FSAN "Enable FSAN (frames sanitizer)" OFF)

set(SAN_CFLAGS "")
if (FRAMES)
  set(SAN_CFLAGS "-fno-omit-frame-pointer -fstack-protector-all")
endif()
if (ASAN)
  set(SAN_CFLAGS "-fno-omit-frame-pointer -fsanitize=address")
endif()
if (TSAN)
  set(SAN_CFLAGS "-fno-omit-frame-pointer -fsanitize=thread")
endif()

set(CMAKE_CXX_FLAGS "-g -fPIC -fPIE -pipe -Wall -Wextra -Werror")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=discarded-qualifiers")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=unused-variable")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=unsafe-loop-optimizations")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wsequence-point")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wredundant-decls")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wshadow")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wfloat-equal")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wcomment -Wparentheses")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wunsafe-loop-optimizations")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SAN_CFLAGS}")

if (NOT CMAKE_BUILD_TYPE)
  message("CMAKE_BUILD_TYPE set to [Release] as a default")
  set(CMAKE_BUILD_TYPE "Release")
endif()
set(CMAKE_CXX_FLAGS_DEBUG          "-O0 -fno-inline")
set(CMAKE_CXX_FLAGS_RELEASE        "-O2")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2")
set(CMAKE_CXX_FLAGS_MINSIZEREL     "-Os")

pkg_search_module(ISALCRYPTO REQUIRED libisal_crypto)
pkg_search_module(GLOG REQUIRED libglog)

add_subdirectory(/usr/src/googletest ${CMAKE_BINARY_DIR}/gtest EXCLUDE_FROM_ALL)

include_directories(
		${ISALCRYPTO_INCLUDE_DIRS}
		${GLOG_INCLUDE_DIRS})

link_directories(
		${ISALCRYPTO_LIBRARY_DIRS}
		${GLOG_LIBRARY_DIRS})

add_library(cpp-isal-crypto SHARED
		src/hash_isal_md5.cpp)
target_link_libraries(cpp-isal-crypto
		${ISALCRYPTO_LIBRARIES}
		${GLOG_LIBRARIES}
		${CMAKE_THREAD_LIBS_INIT})

add_executable(test-cpp-isal-crypto
		test/test_hash_isal_md5.cpp)
target_link_libraries(test-cpp-isal-crypto
		gtest
		cpp-isal-crypto
		${GLOG_LIBRARIES})

gtest_discover_tests(test-cpp-isal-crypto)

add_executable(example-concurrency examples/example_concurrency.cpp)
target_link_libraries(example-concurrency cpp-isal-crypto)

add_executable(example-stream examples/example_stream.cpp)
target_link_libraries(example-stream cpp-isal-crypto)

add_executable(example-simple examples/example_simple.cpp)
target_link_libraries(example-simple cpp-isal-crypto)

if (NOT DEFINED CPPLINT_EXE)
	find_program(CPPLINT_EXE cpplint)
endif ()

if (CPPLINT_EXE)
	add_test(NAME format/src COMMAND
		${CPPLINT_EXE} --recursive --repository=${CMAKE_SOURCE_DIR} --root=src
		${CMAKE_SOURCE_DIR}/src)

	add_test(NAME format/test COMMAND
		${CPPLINT_EXE} --recursive --repository=${CMAKE_SOURCE_DIR} --root=test
		${CMAKE_SOURCE_DIR}/test)

	add_test(NAME format/examples COMMAND
		${CPPLINT_EXE} --recursive --repository=${CMAKE_SOURCE_DIR} --root=examples
		${CMAKE_SOURCE_DIR}/examples)

endif()

