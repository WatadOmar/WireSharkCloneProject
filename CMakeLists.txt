cmake_minimum_required(VERSION 3.23)
project(fantastic_octo_giggle_wireshark C)

set(CMAKE_C_STANDARD 23)

add_executable(fantastic_octo_giggle_wireshark sniffer.c sniffer.h)
