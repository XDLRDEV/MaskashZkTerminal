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
CMAKE_SOURCE_DIR = /home/yuncong/Projects/libsnark

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/yuncong/Projects/libsnark/build

# Utility rule file for NightlyCoverage.

# Include the progress variables for this target.
include src/CMakeFiles/NightlyCoverage.dir/progress.make

src/CMakeFiles/NightlyCoverage:
	cd /home/yuncong/Projects/libsnark/build/src && /usr/bin/ctest -D NightlyCoverage

NightlyCoverage: src/CMakeFiles/NightlyCoverage
NightlyCoverage: src/CMakeFiles/NightlyCoverage.dir/build.make

.PHONY : NightlyCoverage

# Rule to build all files generated by this target.
src/CMakeFiles/NightlyCoverage.dir/build: NightlyCoverage

.PHONY : src/CMakeFiles/NightlyCoverage.dir/build

src/CMakeFiles/NightlyCoverage.dir/clean:
	cd /home/yuncong/Projects/libsnark/build/src && $(CMAKE_COMMAND) -P CMakeFiles/NightlyCoverage.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/NightlyCoverage.dir/clean

src/CMakeFiles/NightlyCoverage.dir/depend:
	cd /home/yuncong/Projects/libsnark/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yuncong/Projects/libsnark /home/yuncong/Projects/libsnark/src /home/yuncong/Projects/libsnark/build /home/yuncong/Projects/libsnark/build/src /home/yuncong/Projects/libsnark/build/src/CMakeFiles/NightlyCoverage.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/NightlyCoverage.dir/depend

