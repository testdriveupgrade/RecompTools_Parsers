cmake_minimum_required(VERSION 3.20)
project(Recomp)

 
# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable SSE4.1 and AVX for clang
add_compile_options(-msse2 -msse3 -msse4.1 -msse4.2 -msse4 -mavx -mavx512f)

# Add source files
file(GLOB PPC_RECOMP_SOURCES
    "ppc/ppc_recomp.*.cpp"
)
set(SOURCES
        main.cpp
        ppc/ppc_func_mapping.cpp
        ${PPC_RECOMP_SOURCES}
        kernal.cpp
)

set(HEADERS
        ppc/ppc_recomp_shared.h
        ppc/ppc_config.h
        ppc/ppc_context.h
)


# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})