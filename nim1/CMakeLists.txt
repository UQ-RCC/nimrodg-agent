project(nim1)

find_package(OpenSSL 2.0.0 REQUIRED)

add_library(nim1 STATIC
		./nim1.cpp
		./include/nim1/nim1.hpp
		./nim1_ip.hpp
		./include/nim1/nim1fwd.hpp

		./make_view.cpp
		./include/nim1/make_view.hpp

		./time.cpp
		./include/nim1/time.hpp

		./lc.cpp
		./include/nim1/lc.hpp

		./crypto_exception.cpp
		./include/nim1/crypto_exception.hpp

		./evpbuf.cpp
		./include/nim1/evpbuf.hpp

		./hmacbuf.cpp
		./include/nim1/hmacbuf.hpp

		./strbuf.cpp
		./include/nim1/strbuf.hpp

		./auth_header.cpp
		./include/nim1/auth_header.hpp

		./signature.cpp
		./include/nim1/signature.hpp
)

set_target_properties(nim1 PROPERTIES
		CXX_STANDARD 17
		CXX_STANDARD_REQUIRED YES
)
target_link_libraries(nim1 PUBLIC
		rabbitmq-c2
		OpenSSL::Crypto
)

target_include_directories(nim1 PUBLIC include)

