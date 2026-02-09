cmake_minimum_required(VERSION 3.18)
project(pycdoc VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

# Find required packages
find_package(Python3 REQUIRED COMPONENTS Interpreter Development.Module)
find_package(SWIG 4.0 REQUIRED)
include(${SWIG_USE_FILE})

# Configure libcdoc build options - disable SWIG in libcdoc, we build it ourselves
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static library" FORCE)
set(FRAMEWORK OFF CACHE BOOL "Disable framework build" FORCE)
set(BUILD_TOOLS OFF CACHE BOOL "Don't build cdoc-tool" FORCE)
set(LIBCDOC_WITH_DOCS OFF CACHE BOOL "Don't build docs" FORCE)

# Override find_package for SWIG within libcdoc scope
# Create a macro that shadows find_package for SWIG
macro(find_package_libcdoc_override)
    if("${ARGV0}" STREQUAL "SWIG")
        # Don't find SWIG - we handle it ourselves
        set(SWIG_FOUND FALSE)
    else()
        _find_package(${ARGV})
    endif()
endmacro()

# Save the real find_package and use our override
cmake_policy(PUSH)
cmake_policy(SET CMP0057 NEW)
macro(_find_package)
    find_package(${ARGV})
endmacro()

# Temporarily replace find_package with our override before adding libcdoc
macro(find_package)
    find_package_libcdoc_override(${ARGV})
endmacro()

# Add libcdoc as subdirectory
add_subdirectory(libcdoc)

# Restore find_package
cmake_policy(POP)
macro(find_package)
    _find_package(${ARGV})
endmacro()

# Set up SWIG for Python - use libcdoc as module name (matches SWIG %module directive)
set(CMAKE_SWIG_FLAGS "")
set_property(SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/libcdoc/libcdoc.i PROPERTY CPLUSPLUS ON)
set_property(SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/libcdoc/libcdoc.i PROPERTY SWIG_MODULE_NAME libcdoc)
# Set SWIG include directories
set_property(SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/libcdoc/libcdoc.i
    PROPERTY INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libcdoc/cdoc)

# Create the Python extension
swig_add_library(pycdoc_swig
    TYPE MODULE
    LANGUAGE python
    OUTPUT_DIR ${CMAKE_BINARY_DIR}/pycdoc
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/libcdoc/libcdoc.i
)

# Include directories for C++ compilation
target_include_directories(pycdoc_swig PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/libcdoc/cdoc
    ${Python3_INCLUDE_DIRS}
)

# Set output name to _libcdoc (SWIG convention: _<module_name>)
set_target_properties(pycdoc_swig PROPERTIES
    OUTPUT_NAME "_libcdoc"
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/pycdoc
    SWIG_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libcdoc/cdoc
)

# Link against cdoc and Python
target_link_libraries(pycdoc_swig PRIVATE
    cdoc
    Python3::Module
)

# On macOS, handle rpath for finding libraries
if(APPLE)
    set_target_properties(pycdoc_swig PROPERTIES
        INSTALL_RPATH "@loader_path"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
endif()

# Install targets for scikit-build-core
# The wheel.install-dir in pyproject.toml is set to "pycdoc"
# so we install relative to that
install(TARGETS pycdoc_swig
    LIBRARY DESTINATION .
    RUNTIME DESTINATION .
)

# Install the SWIG-generated Python wrapper (libcdoc.py)
install(FILES ${CMAKE_BINARY_DIR}/pycdoc/libcdoc.py
    DESTINATION .
)

# Install the package __init__.py
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/pycdoc/__init__.py
    DESTINATION .
)
