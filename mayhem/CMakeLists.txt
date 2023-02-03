add_executable(fuzz_casc fuzz_load.cpp)

target_compile_options(fuzz_casc PRIVATE -fsanitize=fuzzer,address,undefined)
target_link_options(fuzz_casc PRIVATE -fsanitize=fuzzer,address,undefined)

target_link_libraries(fuzz_casc casc)