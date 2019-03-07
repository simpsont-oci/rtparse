cmake_minimum_required (VERSION 2.6)
project (spdp_snooper)

find_package (Boost COMPONENTS program_options REQUIRED)

SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall -pedantic -Werror -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused -g -std=c++14")

add_executable(rtparse rtparse.cpp)

target_link_libraries(rtparse LINK_PUBLIC ${Boost_LIBRARIES})

