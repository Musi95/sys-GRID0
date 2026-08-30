/*
 * sys-zerotier -- stub for <endian.h>.
 *
 * devkitA64's newlib has no <endian.h>. node/Constants.hpp includes it for one
 * reason only: to get __BYTE_ORDER when the compiler has not already defined
 * it. GCC always knows, so take it from there and skip the dependency.
 */
#pragma once

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN    __ORDER_BIG_ENDIAN__
#endif
#ifndef __PDP_ENDIAN
#define __PDP_ENDIAN    __ORDER_PDP_ENDIAN__
#endif
#ifndef __BYTE_ORDER
#define __BYTE_ORDER    __BYTE_ORDER__
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN   __LITTLE_ENDIAN
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN      __BIG_ENDIAN
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER      __BYTE_ORDER
#endif
