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

# Utility rule file for NightlyStart.

# Include the progress variables for this target.
include src/CMakeFiles/NightlyStart.dir/progress.make

src/CMakeFiles/NightlyStart:
	cd /home/yuncong/Projects/libff/build/src && /usr/bin/ctest -D NightlyStart

NightlyStart: src/CMakeFiles/NightlyStart
NightlyStart: src/CMakeFiles/NightlyStart.dir/build.make

.PHONY : NightlyStart

# Rule to build all files generated by this target.
src/CMakeFiles/NightlyStart.dir/build: NightlyStart

.PHONY : src/CMakeFiles/NightlyStart.dir/build

src/CMakeFiles/NightlyStart.dir/clean:
	cd /home/yuncong/Projects/libff/build/src && $(CMAKE_COMMAND) -P CMakeFiles/NightlyStart.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/NightlyStart.dir/clean

src/CMakeFiles/NightlyStart.dir/depend:
	cd /home/yuncong/Projects/libff/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yuncong/Projects/libff /home/yuncong/Projects/libff/src /home/yuncong/Projects/libff/build /home/yuncong/Projects/libff/build/src /home/yuncong/Projects/libff/build/src/CMakeFiles/NightlyStart.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/NightlyStart.dir/depend

