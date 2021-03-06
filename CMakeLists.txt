cmake_minimum_required (VERSION 2.6)
project (spdp_snooper)

find_package (Boost COMPONENTS program_options REQUIRED)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall -pedantic -Werror -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wmissing-declarations -Wmissing-include-dirs -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused -g -std=c++14")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall -pedantic -Werror -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused -g -std=c++14")
endif()

add_executable(rtparse src/fuzzy_bool.cpp src/utils.cpp src/frames.cpp src/tshark_parsing.cpp src/info_pairs.cpp src/net_info.cpp src/endpoint_info.cpp src/filtering.cpp src/conversation_info.cpp src/main.cpp)

target_include_directories(rtparse PUBLIC src)
target_link_libraries(rtparse LINK_PUBLIC ${Boost_LIBRARIES})

