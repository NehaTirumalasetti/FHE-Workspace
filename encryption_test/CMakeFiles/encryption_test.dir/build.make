# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

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
CMAKE_SOURCE_DIR = /opt/IBM/FHE-Workspace/encryption_test

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /opt/IBM/FHE-Workspace/encryption_test

# Include any dependencies generated for this target.
include CMakeFiles/encryption_test.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/encryption_test.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/encryption_test.dir/flags.make

CMakeFiles/encryption_test.dir/test.cpp.o: CMakeFiles/encryption_test.dir/flags.make
CMakeFiles/encryption_test.dir/test.cpp.o: test.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/opt/IBM/FHE-Workspace/encryption_test/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/encryption_test.dir/test.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/encryption_test.dir/test.cpp.o -c /opt/IBM/FHE-Workspace/encryption_test/test.cpp

CMakeFiles/encryption_test.dir/test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/encryption_test.dir/test.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /opt/IBM/FHE-Workspace/encryption_test/test.cpp > CMakeFiles/encryption_test.dir/test.cpp.i

CMakeFiles/encryption_test.dir/test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/encryption_test.dir/test.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /opt/IBM/FHE-Workspace/encryption_test/test.cpp -o CMakeFiles/encryption_test.dir/test.cpp.s

# Object files for target encryption_test
encryption_test_OBJECTS = \
"CMakeFiles/encryption_test.dir/test.cpp.o"

# External object files for target encryption_test
encryption_test_EXTERNAL_OBJECTS =

encryption_test: CMakeFiles/encryption_test.dir/test.cpp.o
encryption_test: CMakeFiles/encryption_test.dir/build.make
encryption_test: /usr/lib/x86_64-linux-gnu/hdf5/serial/libhdf5_cpp.so
encryption_test: /usr/lib/x86_64-linux-gnu/hdf5/serial/libhdf5.so
encryption_test: /usr/lib/x86_64-linux-gnu/libpthread.so
encryption_test: /usr/lib/x86_64-linux-gnu/libsz.so
encryption_test: /usr/lib/x86_64-linux-gnu/libz.so
encryption_test: /usr/lib/x86_64-linux-gnu/libdl.so
encryption_test: /usr/lib/x86_64-linux-gnu/libm.so
encryption_test: /usr/local/lib/libboost_filesystem.so.1.72.0
encryption_test: /usr/local/lib/libhelib.so.1.1.0
encryption_test: /usr/local/lib/libntl.so
encryption_test: /usr/lib/x86_64-linux-gnu/libgmp.so
encryption_test: CMakeFiles/encryption_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/opt/IBM/FHE-Workspace/encryption_test/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable encryption_test"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/encryption_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/encryption_test.dir/build: encryption_test

.PHONY : CMakeFiles/encryption_test.dir/build

CMakeFiles/encryption_test.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/encryption_test.dir/cmake_clean.cmake
.PHONY : CMakeFiles/encryption_test.dir/clean

CMakeFiles/encryption_test.dir/depend:
	cd /opt/IBM/FHE-Workspace/encryption_test && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /opt/IBM/FHE-Workspace/encryption_test /opt/IBM/FHE-Workspace/encryption_test /opt/IBM/FHE-Workspace/encryption_test /opt/IBM/FHE-Workspace/encryption_test /opt/IBM/FHE-Workspace/encryption_test/CMakeFiles/encryption_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/encryption_test.dir/depend

