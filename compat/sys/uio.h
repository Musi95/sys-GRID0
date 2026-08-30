/*
 * sys-zerotier -- stub for <sys/uio.h>.
 *
 * newlib does not ship it. node/Utils.cpp includes it and then never uses
 * anything from it: there is not a single iovec, readv or writev anywhere in
 * ZeroTier's core.
 *
 * struct iovec itself does exist on this toolchain -- libnx declares it in
 * <sys/_iovec.h>, which <sys/socket.h> pulls in -- so defer to that rather
 * than defining a second copy.
 */
#pragma once

#include <sys/types.h>

#if defined(__has_include)
#if __has_include(<sys/_iovec.h>)
#include <sys/_iovec.h>
#define ZTNX_HAVE_IOVEC 1
#endif
#endif

#ifndef ZTNX_HAVE_IOVEC
struct iovec {
    void  *iov_base;
    size_t iov_len;
};
#endif
