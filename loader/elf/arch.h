#ifndef _ARCH_H_
#define _ARCH_H_

#if defined(OS_LINUX)
#if defined(ARCH_ARMEL)
#include "sysdep/linux/armel/arch.h"
#elif defined(ARCH_ARMEL_THUMB)
#include "sysdep/linux/armel_thumb/arch.h"
#elif defined(ARCH_ARMEB)
#include "sysdep/linux/armeb/arch.h"
#elif defined(ARCH_ARMEB_THUMB)
#include "sysdep/linux/armeb_thumb/arch.h"
#elif defined(ARCH_I686)
#include "sysdep/linux/i686/arch.h"
#elif defined(ARCH_X86_64)
#include "sysdep/linux/x86_64/arch.h"
#elif defined(ARCH_MIPS)
#include "sysdep/linux/mips/arch.h"
#elif defined(ARCH_MIPSEL)
#include "sysdep/linux/mipsel/arch.h"
#elif defined(ARCH_MIPS64)
#include "sysdep/linux/mips64/arch.h"
#elif defined(ARCH_PPC32)
#include "sysdep/linux/ppc32/arch.h"
#elif defined(ARCH_PPC64)
#include "sysdep/linux/ppc64/arch.h"
#elif defined(ARCH_SPARC)
#include "sysdep/linux/sparc/arch.h"
#elif defined(ARCH_SPARC64)
#include "sysdep/linux/sparc64/arch.h"
#elif defined(ARCH_SH4)
#include "sysdep/linux/sh4/arch.h"
#elif defined(ARCH_SH4EB)
#include "sysdep/linux/sh4eb/arch.h"
#elif defined(ARCH_MICROBLAZE)
#include "sysdep/linux/microblaze/arch.h"
#elif defined(ARCH_MICROBLAZEEL)
#include "sysdep/linux/microblazeel/arch.h"
#elif defined(ARCH_ALPHA)
#include "sysdep/linux/alpha/arch.h"
#elif defined(ARCH_CRISV32)
#include "sysdep/linux/crisv32/arch.h"
#elif defined(ARCH_S390X)
#include "sysdep/linux/s390x/arch.h"
#elif defined(ARCH_ARM64)
#include "sysdep/linux/arm64/arch.h"
#else
#error "No architecture specified!"
#endif // Linux

#elif defined(OS_FREEBSD)
#if defined(ARCH_X86)
#include "sysdep/freebsd/x86/arch.h"
#elif defined(ARCH_X86_64)
#include "sysdep/freebsd/x86_64/arch.h"
#else
#error "No architecture specified!"
#endif // FREEBSD

#elif defined(OS_NETBSD)
#if defined(ARCH_X86)
#include "sysdep/netbsd/x86/arch.h"
#elif defined(ARCH_X86_64)
#include "sysdep/netbsd/x86_64/arch.h"
#else
#error "No architecture specified!"
#endif // NETBSD

#else
#endif // OS

#endif // _ARCH_H_
