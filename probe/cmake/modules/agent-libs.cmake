#
# Copyright (C) 2013-2021 Draios Inc dba Sysdig.
#
# This file is part of sysdig .
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set(AGENT_LIBS_CMAKE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/agent-libs-repo")
set(AGENT_LIBS_CMAKE_WORKING_DIR "${CMAKE_BINARY_DIR}/agent-libs-repo")

add_definitions(-DHAS_CAPTURE)
add_definitions(-DMINIMAL_BUILD)

file(MAKE_DIRECTORY ${AGENT_LIBS_CMAKE_WORKING_DIR})

if(AGENT_LIBS_SOURCE_DIR)
  set(AGENT_LIBS_VERSION "local")
  message(STATUS "Using local falcosecurity/libs in '${AGENT_LIBS_SOURCE_DIR}'")
else()
  # The falcosecurity/libs git reference (branch name, commit hash, or tag) To update falcosecurity/libs version for the next release, change the
  # default below In case you want to test against another falcosecurity/libs version just pass the variable - ie., `cmake
  # -DAGENT_LIBS_VERSION=dev ..`
  if(NOT AGENT_LIBS_VERSION)
    set(AGENT_LIBS_VERSION "cb32bd10cb8f60df3605040586e1ed29bf8d4ebc")
    set(AGENT_LIBS_CHECKSUM "SHA256=780af217a28562ec4a8940a917bb3417b056c70abefd7a30c108bc9adc272a1c")
  endif()

  # cd /path/to/build && cmake /path/to/source
  execute_process(COMMAND "${CMAKE_COMMAND}" -DAGENT_LIBS_VERSION=${AGENT_LIBS_VERSION} -DAGENT_LIBS_CHECKSUM=${AGENT_LIBS_CHECKSUM}
                          ${AGENT_LIBS_CMAKE_SOURCE_DIR} WORKING_DIRECTORY ${AGENT_LIBS_CMAKE_WORKING_DIR})

  # todo(leodido, fntlnz) > use the following one when CMake version will be >= 3.13

  # execute_process(COMMAND "${CMAKE_COMMAND}" -B ${AGENT_LIBS_CMAKE_WORKING_DIR} WORKING_DIRECTORY
  # "${AGENT_LIBS_CMAKE_SOURCE_DIR}")

  execute_process(COMMAND "${CMAKE_COMMAND}" --build . WORKING_DIRECTORY "${AGENT_LIBS_CMAKE_WORKING_DIR}")
  set(AGENT_LIBS_SOURCE_DIR "${AGENT_LIBS_CMAKE_WORKING_DIR}/agent-libs-prefix/src/agent-libs")
endif()

set(DRIVER_VERSION "${AGENT_LIBS_VERSION}")

if(NOT LIBSCAP_DIR)
  set(LIBSCAP_DIR "${AGENT_LIBS_SOURCE_DIR}")
endif()
set(LIBSINSP_DIR "${AGENT_LIBS_SOURCE_DIR}")

set(CREATE_TEST_TARGETS OFF CACHE BOOL "")
set(BUILD_LIBSCAP_EXAMPLES OFF CACHE BOOL "")
set(BUILD_LIBSINSP_EXAMPLES OFF CACHE BOOL "")

list(APPEND CMAKE_MODULE_PATH "${LIBSCAP_DIR}/cmake/modules")
list(APPEND CMAKE_MODULE_PATH "${LIBSINSP_DIR}/cmake/modules")

include(CheckSymbolExists)
check_symbol_exists(strlcpy "string.h" HAVE_STRLCPY)
if(HAVE_STRLCPY)
	message(STATUS "Existing strlcpy found, will *not* use local definition by setting -DHAVE_STRLCPY.")
	add_definitions(-DHAVE_STRLCPY)
else()
	message(STATUS "No strlcpy found, will use local definition")
endif()

include(libscap)
include(libsinsp)