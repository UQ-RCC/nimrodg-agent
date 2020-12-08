##
# This is just a copy of libuuid/*.{c,h} from the util-linux
# source tree at git tag 2.36.1.
#
# Embedding because util-linux itself has too many dependencies.
#
# Notes:
# - gen_uuid.c - Does special things for generation. Excluded because
#   we just use LibreSSL.
# - test_uuid.c - Excluded because not needed.
##
project(libuuid)

add_library(libuuid STATIC
        clear.c
        compare.c
        copy.c
        isnull.c
        pack.c
        parse.c
        predefined.c
        unpack.c
        unparse.c
        uuidd.h
        uuid.h
        uuidP.h
        uuid_time.c

        # NB: Excluding these.
        # gen_uuid.c requires special configuration, where we're just
        # using OpenSSL.
        # test_uuid.c has nothing to do with us.
        #gen_uuid.c
        #test_uuid.c
)

target_include_directories(libuuid PUBLIC .)
set_target_properties(libuuid PROPERTIES VERSION "2.36.1")
