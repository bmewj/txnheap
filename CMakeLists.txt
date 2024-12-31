cmake_minimum_required(VERSION 3.14)
project(txnheap VERSION 0.0.0)
set(CMAKE_CXX_STANDARD 17)

add_library(txnheap STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/txnheap.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/txnheap.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/txnheap_btree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/txnheap_btree.h
)
target_include_directories(txnheap PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/
)

add_executable(txnheap-example
    ${CMAKE_CURRENT_SOURCE_DIR}/example/main.cpp
)
target_link_libraries(txnheap-example
    txnheap
)
