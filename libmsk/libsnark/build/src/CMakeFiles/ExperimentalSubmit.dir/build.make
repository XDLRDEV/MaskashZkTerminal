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

# Utility rule file for ExperimentalSubmit.

# Include the progress variables for this target.
include src/CMakeFiles/ExperimentalSubmit.dir/progress.make

src/CMakeFiles/ExperimentalSubmit:
	cd /home/yuncong/Projects/libsnark/build/src && /usr/bin/ctest -D ExperimentalSubmit

ExperimentalSubmit: src/CMakeFiles/ExperimentalSubmit
ExperimentalSubmit: src/CMakeFiles/ExperimentalSubmit.dir/build.make

.PHONY : ExperimentalSubmit

# Rule to build all files generated by this target.
src/CMakeFiles/ExperimentalSubmit.dir/build: ExperimentalSubmit

.PHONY : src/CMakeFiles/ExperimentalSubmit.dir/build

src/CMakeFiles/ExperimentalSubmit.dir/clean:
	cd /home/yuncong/Projects/libsnark/build/src && $(CMAKE_COMMAND) -P CMakeFiles/ExperimentalSubmit.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/ExperimentalSubmit.dir/clean

src/CMakeFiles/ExperimentalSubmit.dir/depend:
	cd /home/yuncong/Projects/libsnark/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yuncong/Projects/libsnark /home/yuncong/Projects/libsnark/src /home/yuncong/Projects/libsnark/build /home/yuncong/Projects/libsnark/build/src /home/yuncong/Projects/libsnark/build/src/CMakeFiles/ExperimentalSubmit.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/ExperimentalSubmit.dir/depend

