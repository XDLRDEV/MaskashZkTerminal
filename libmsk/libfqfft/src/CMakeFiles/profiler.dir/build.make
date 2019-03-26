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
CMAKE_SOURCE_DIR = /home/yuncong/Projects/libfqfft

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/yuncong/Projects/libfqfft

# Include any dependencies generated for this target.
include src/CMakeFiles/profiler.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/profiler.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/profiler.dir/flags.make

src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o: src/CMakeFiles/profiler.dir/flags.make
src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o: src/profiling/profile/profile.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/yuncong/Projects/libfqfft/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o"
	cd /home/yuncong/Projects/libfqfft/src && /usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o -c /home/yuncong/Projects/libfqfft/src/profiling/profile/profile.cpp

src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/profiler.dir/profiling/profile/profile.cpp.i"
	cd /home/yuncong/Projects/libfqfft/src && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/yuncong/Projects/libfqfft/src/profiling/profile/profile.cpp > CMakeFiles/profiler.dir/profiling/profile/profile.cpp.i

src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/profiler.dir/profiling/profile/profile.cpp.s"
	cd /home/yuncong/Projects/libfqfft/src && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/yuncong/Projects/libfqfft/src/profiling/profile/profile.cpp -o CMakeFiles/profiler.dir/profiling/profile/profile.cpp.s

src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o.requires:

.PHONY : src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o.requires

src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o.provides: src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o.requires
	$(MAKE) -f src/CMakeFiles/profiler.dir/build.make src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o.provides.build
.PHONY : src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o.provides

src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o.provides.build: src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o


# Object files for target profiler
profiler_OBJECTS = \
"CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o"

# External object files for target profiler
profiler_EXTERNAL_OBJECTS =

profiler: src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o
profiler: src/CMakeFiles/profiler.dir/build.make
profiler: /usr/local/lib/libff.a
profiler: /usr/lib/x86_64-linux-gnu/libgmp.so
profiler: /usr/lib/x86_64-linux-gnu/libgmpxx.so
profiler: src/CMakeFiles/profiler.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/yuncong/Projects/libfqfft/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../profiler"
	cd /home/yuncong/Projects/libfqfft/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/profiler.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/profiler.dir/build: profiler

.PHONY : src/CMakeFiles/profiler.dir/build

src/CMakeFiles/profiler.dir/requires: src/CMakeFiles/profiler.dir/profiling/profile/profile.cpp.o.requires

.PHONY : src/CMakeFiles/profiler.dir/requires

src/CMakeFiles/profiler.dir/clean:
	cd /home/yuncong/Projects/libfqfft/src && $(CMAKE_COMMAND) -P CMakeFiles/profiler.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/profiler.dir/clean

src/CMakeFiles/profiler.dir/depend:
	cd /home/yuncong/Projects/libfqfft && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/yuncong/Projects/libfqfft /home/yuncong/Projects/libfqfft/src /home/yuncong/Projects/libfqfft /home/yuncong/Projects/libfqfft/src /home/yuncong/Projects/libfqfft/src/CMakeFiles/profiler.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/profiler.dir/depend

