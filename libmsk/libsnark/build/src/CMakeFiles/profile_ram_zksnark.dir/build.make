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

# Include any dependencies generated for this target.
include src/CMakeFiles/profile_ram_zksnark.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/profile_ram_zksnark.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/profile_ram_zksnark.dir/flags.make

src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o: src/CMakeFiles/profile_ram_zksnark.dir/flags.make
src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o: ../src/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yuncong/Projects/libsnark/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o"
	cd /home/yuncong/Projects/libsnark/build/src && /usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o -c /home/yuncong/Projects/libsnark/src/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp

src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.i"
	cd /home/yuncong/Projects/libsnark/build/src && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yuncong/Projects/libsnark/src/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp > CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.i

src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.s"
	cd /home/yuncong/Projects/libsnark/build/src && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yuncong/Projects/libsnark/src/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp -o CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.s

src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.requires:

.PHONY : src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.requires

src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.provides: src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.requires
	$(MAKE) -f src/CMakeFiles/profile_ram_zksnark.dir/build.make src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.provides.build
.PHONY : src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.provides

src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.provides.build: src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o


# Object files for target profile_ram_zksnark
profile_ram_zksnark_OBJECTS = \
"CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o"

# External object files for target profile_ram_zksnark
profile_ram_zksnark_EXTERNAL_OBJECTS =

src/profile_ram_zksnark: src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o
src/profile_ram_zksnark: src/CMakeFiles/profile_ram_zksnark.dir/build.make
src/profile_ram_zksnark: src/libsnark.a
src/profile_ram_zksnark: /usr/lib/x86_64-linux-gnu/libboost_program_options.so
src/profile_ram_zksnark: /usr/lib/x86_64-linux-gnu/libgmp.so
src/profile_ram_zksnark: /usr/lib/x86_64-linux-gnu/libgmpxx.so
src/profile_ram_zksnark: /usr/local/lib/libff.a
src/profile_ram_zksnark: /usr/local/lib/libff.a
src/profile_ram_zksnark: third_party/libzm.a
src/profile_ram_zksnark: src/CMakeFiles/profile_ram_zksnark.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/yuncong/Projects/libsnark/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable profile_ram_zksnark"
	cd /home/yuncong/Projects/libsnark/build/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/profile_ram_zksnark.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/profile_ram_zksnark.dir/build: src/profile_ram_zksnark

.PHONY : src/CMakeFiles/profile_ram_zksnark.dir/build

src/CMakeFiles/profile_ram_zksnark.dir/requires: src/CMakeFiles/profile_ram_zksnark.dir/zk_proof_systems/zksnark/ram_zksnark/profiling/profile_ram_zksnark.cpp.o.requires

.PHONY : src/CMakeFiles/profile_ram_zksnark.dir/requires

src/CMakeFiles/profile_ram_zksnark.dir/clean:
	cd /home/yuncong/Projects/libsnark/build/src && $(CMAKE_COMMAND) -P CMakeFiles/profile_ram_zksnark.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/profile_ram_zksnark.dir/clean

src/CMakeFiles/profile_ram_zksnark.dir/depend:
	cd /home/yuncong/Projects/libsnark/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yuncong/Projects/libsnark /home/yuncong/Projects/libsnark/src /home/yuncong/Projects/libsnark/build /home/yuncong/Projects/libsnark/build/src /home/yuncong/Projects/libsnark/build/src/CMakeFiles/profile_ram_zksnark.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/profile_ram_zksnark.dir/depend

