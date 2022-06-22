# required CMake version
cmake_minimum_required (VERSION 2.8)

# project info 
project (BGVNaiveBayesPredictor)

set(CMAKE_CXX_STANDARD 17)

set(BGVNBP_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)

set(SOURCE_FILES 
                ${BGVNBP_SOURCE_DIR}/naiveBayes.cpp  
                ${BGVNBP_SOURCE_DIR}/tools.cpp  
                ${BGVNBP_SOURCE_DIR}/comparator.cpp
                ${BGVNBP_SOURCE_DIR}/matrix.cpp
                ${BGVNBP_SOURCE_DIR}/utils.cpp)

include_directories(${BGVNBP_SOURCE_DIR})


# specify objective to be generated
add_executable (BGVNaiveBayesPredictor ${SOURCE_FILES})
target_link_libraries(BGVNaiveBayesPredictor helib ntl pthread)
