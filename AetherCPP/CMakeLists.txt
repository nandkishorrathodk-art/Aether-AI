cmake_minimum_required(VERSION 3.20)
project(AetherCPP VERSION 0.3.0 LANGUAGES CXX)

# C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optimization flags
if(CMAKE_BUILD_TYPE MATCHES Release)
    if(MSVC)
        add_compile_options(/O2 /arch:AVX2)
    else()
        add_compile_options(-O3 -march=native -mavx2)
    endif()
endif()

# Find dependencies
find_package(pybind11 CONFIG)
find_package(OpenCV CONFIG)

# Audio Processing Library
add_library(aether_audio SHARED
    audio/AudioProcessor.cpp
    audio/VoiceAnalyzer.cpp
    audio/NoiseReduction.cpp
)

target_include_directories(aether_audio PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# ML Inference Library  
add_library(aether_ml SHARED
    ml/InferenceEngine.cpp
    ml/Quantization.cpp
    ml/ModelOptimizer.cpp
)

target_include_directories(aether_ml PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Video Processing Library
if(OpenCV_FOUND)
    add_library(aether_video SHARED
        video/FrameProcessor.cpp
        video/ObjectDetection.cpp
    )
    target_link_libraries(aether_video ${OpenCV_LIBS})
endif()

# Python Bindings
if(pybind11_FOUND)
    pybind11_add_module(aether_cpp 
        bindings/python_bindings.cpp
    )
    target_link_libraries(aether_cpp PRIVATE aether_audio aether_ml)
endif()

# Installation
install(TARGETS aether_audio aether_ml 
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
