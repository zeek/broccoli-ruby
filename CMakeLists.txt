project(RbBroccoli)

########################################################################
## CMake Configuration

cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

# Prohibit in-source builds.
if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "In-source builds are not allowed. Please use "
                        "./configure to choose a build directory and "
                        "initialize the build configuration.")
endif ()

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # uninstall target
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
                    @ONLY)

    add_custom_target(uninstall COMMAND
        ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif ()

# Keep RPATH upon installing so that user doesn't have to ensure the linker
# can find internal/private libraries or libraries external to the build
# directory that were explicitly linked against
if (NOT BINARY_PACKAGING_MODE)
    SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
endif ()

########################################################################
## Project/Build Configuration

if (ENABLE_DEBUG)
    set(CMAKE_BUILD_TYPE Debug)
else ()
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif ()

# don't set extra compile flags again if already declared in this scope
# (i.e. this project is included from Bro)
if (NOT EXTRA_COMPILE_FLAGS)
    set(EXTRA_COMPILE_FLAGS "-Wall -Wno-unused")

    if (ENABLE_DEBUG)
        set(EXTRA_COMPILE_FLAGS "${EXTRA_COMPILE_FLAGS} -DDEBUG")
    endif ()

    # Compiler flags may already exist in CMake cache (e.g. when specifying
    # CFLAGS environment variable before running cmake for the the first time)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_COMPILE_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXTRA_COMPILE_FLAGS}")
endif ()

########################################################################
## Dependency Configuration

include(MacDependencyPaths)
include(FindRequiredPackage)

FindRequiredPackage(Broccoli)
FindRequiredPackage(SWIG)

set(Ruby_FIND_VERSION_MAJOR 1)
set(Ruby_FIND_VERSION_MINOR 8)
FindRequiredPackage(Ruby)

if (MISSING_PREREQS)
    foreach (prereq ${MISSING_PREREQ_DESCS})
        message(SEND_ERROR ${prereq})
    endforeach ()
    message(FATAL_ERROR "Configuration aborted due to missing prerequisites")
endif ()

if (RUBY_INCLUDE_PATH)
    # CMake 2.6 compatibility -- FindRuby used to set RUBY_INCLUDE_PATH
    include_directories(BEFORE ${RUBY_INCLUDE_PATH})
else ()
    include_directories(BEFORE ${RUBY_INCLUDE_DIRS})
endif ()

include_directories(BEFORE ${Broccoli_INCLUDE_DIR})

########################################################################
## Build Ruby Extension

include(UseSWIG)

set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/ext/broccoli)
swig_add_module(broccoli_intern RUBY ext/broccoli/broccoli_intern.i)
swig_link_libraries(broccoli_intern ${Broccoli_LIBRARY} ${RUBY_LIBRARY})

########################################################################
## Install Files

if (NOT RB_MOD_INSTALL_DIR)
    # the configure wrapper was not used, default to "home" style installation
    set(RB_MOD_INSTALL_DIR lib/ruby)
endif ()

install(FILES broccoli.rb
        DESTINATION ${RB_MOD_INSTALL_DIR})
install(TARGETS ${SWIG_MODULE_broccoli_intern_REAL_NAME}
        DESTINATION ${RB_MOD_INSTALL_DIR})

########################################################################
## Build Summary

if (CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)
endif ()

message(
    "\n================|  RbBroccoli Build Summary  |=================="
    "\n"
    "\nInstall dir:       ${RB_MOD_INSTALL_DIR}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:               ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_CXX_COMPILER}"
    "\n"
    "\n================================================================\n"
)

########################################################################
## Show warning when installing user is different from the one that configured

install(CODE "
    if (NOT $ENV{USER} STREQUAL \$ENV{USER})
        message(STATUS \"ATTENTION: Install is being performed by user \"
                \"'\$ENV{USER}', but the build directory was configured by \"
                \"user '$ENV{USER}'. This may result in a permissions error \"
                \"when writing the install manifest, but you can ignore it \"
                \"and consider the installation as successful if you don't \"
                \"care about the install manifest.\")
    endif ()
")
