# cmake_minimum_required(VERSION 2.6)
# project(senzorlinux)

# add_executable(senzorlinux main.cpp)

# install(TARGETS senzorlinux RUNTIME DESTINATION bin)


# Set project name
project (AgentLinux)

# Set minimum version
cmake_minimum_required (VERSION 2.8.6)

if (COMMAND cmake_policy)
  cmake_policy (SET CMP0003 NEW)
  if (CMAKE_VERSION VERSION_GREATER 2.8.12 OR CMAKE_VERSION VERSION_EQUAL 2.8.12)
    # INTERFACE_LINK_LIBRARIES defines the link interface
    cmake_policy (SET CMP0022 NEW)
  endif ()
  if (CMAKE_VERSION VERSION_GREATER 3.0.0 OR CMAKE_VERSION VERSION_EQUAL 3.0.0)
  # Disallow use of the LOCATION target property - therefore we set to OLD as we still need it
    cmake_policy (SET CMP0026 OLD)
    # MACOSX_RPATH is enabled by default
    cmake_policy (SET CMP0042 NEW)
  endif ()
endif ()

# Set CMake modules search path
# set (CMAKE_MODULE_PATH "/home/projekty/Hry/TuxKing/CMake/Modules")

# Include Urho3D Cmake common module
# include (Urho3D-CMake-common)

# Find Urho3D library
# find_package (Urho3D REQUIRED)
# include_directories (/home/projekty/Hry/Urho3D/Urho3D/include/Urho3D /home/projekty/Hry/Urho3D/Urho3D/include/Urho3D/ThirdParty)


# Define target name
set (TARGET_NAME AgentLinux)


# Define source files
#define_source_files ()

file (GLOB CPP_FILES *.cpp)
file (GLOB H_FILES *.h)

file (GLOB CONF_CPP_FILES config/*.cpp)
file (GLOB CONF_H_FILES config/*.h)

file (GLOB DEBUG_CPP_FILES debugger/*.cpp)
file (GLOB DEBUG_H_FILES debugger/*.h)

file (GLOB EXCEPT_CPP_FILES exceptions/*.cpp)
file (GLOB EXCEPT_H_FILES exceptions/*.h)

file (GLOB LOG_CPP_FILES log/*.cpp)
file (GLOB LOG_H_FILES log/*.h)

file (GLOB SNIFF_CPP_FILES packet_sniffer/*.cpp)
file (GLOB SNIFF_H_FILES packet_sniffer/*.h)


set (SOURCE_FILES ${CPP_FILES} ${H_FILES} ${CONF_CPP_FILES} ${CONF_H_FILES} ${DB_CPP_FILES} ${DB_H_FILES} ${DEBUG_CPP_FILES} ${DEBUG_H_FILES} ${EXCEPT_CPP_FILES} ${EXCEPT_H_FILES} ${LOG_CPP_FILES} ${LOG_H_FILES} ${SNIFF_CPP_FILES} ${SNIFF_H_FILES})

# using dynamic libs
if(EXISTS /usr/lib/x86_64-linux-gnu/libpcap.so)
  set (LIBS /usr/local/lib/libmysqlpp.so /usr/lib/x86_64-linux-gnu/libpcap.so)
else()
  set (LIBS /usr/lib/libmysqlpp.so /usr/lib/i386-linux-gnu/libpcap.so)
endif()

# find_library(/usr/lib/libmysqlpp.so libmysqlpp)
# message("Lib1 is at: /usr/lib/libmysqlpp.so")
# target_link_libraries(lib2 LINK_PUBLIC /usr/lib/libmysqlpp.so)


# Setup target with resource copying
# setup_main_executable ()
add_executable(AgentLinux ${SOURCE_FILES})
target_link_libraries(AgentLinux -lpthread ${LIBS})

#find_package(Threads)

# 32bit application
# set_target_properties(senzorlinux PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
