# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.7

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/yuncong/Projects/libff

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/yuncong/Projects/libff/build

# Utility rule file for NightlyConfigure.

# Include the progress variables for this target.
include src/CMakeFiles/NightlyConfigure.dir/progress.make

src/CMakeFiles/NightlyConfigure:
	cd /home/yuncong/Projects/libff/build/src && /usr/bin/ctest -D NightlyConfigure

NightlyConfigure: src/CMakeFiles/NightlyConfigure
NightlyConfigure: src/CMakeFiles/NightlyConfigure.dir/build.make

.PHONY : NightlyConfigure

# Rule to build all files generated by this target.
src/CMakeFiles/NightlyConfigure.dir/build: NightlyConfigure

.PHONY : src/CMakeFiles/NightlyConfigure.dir/build

src/CMakeFiles/NightlyConfigure.dir/clean:
	cd /home/yuncong/Projects/libff/build/src && $(CMAKE_COMMAND) -P CMakeFiles/NightlyConfigure.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/NightlyConfigure.dir/clean

src/CMakeFiles/NightlyConfigure.dir/depend:
	cd /home/yuncong/Projects/libff/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yuncong/Projects/libff /home/yuncong/Projects/libff/src /home/yuncong/Projects/libff/build /home/yuncong/Projects/libff/build/src /home/yuncong/Projects/libff/build/src/CMakeFiles/NightlyConfigure.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/NightlyConfigure.dir/depend

