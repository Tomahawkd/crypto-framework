# essentials
add_subdirectory(wrp)
add_subdirectory(random)
add_subdirectory(wrpio)

# propogate list
LIST(SORT SRC_FILES)
set(SRC_FILES ${SRC_FILES} PARENT_SCOPE)
set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} PARENT_SCOPE)