project(nim1)

add_library(nim1 STATIC
		./nim1.cpp
		./include/nim1/nim1.hpp
		./nim1_ip.hpp
		./include/nim1/nim1fwd.hpp

		./make_view.cpp
		./include/nim1/make_view.hpp
)

set_target_properties(nim1 PROPERTIES
		CXX_STANDARD 17
		CXX_STANDARD_REQUIRED YES
)
target_link_libraries(nim1 PUBLIC
		rabbitmq-c2
)

target_include_directories(nim1 PUBLIC include)