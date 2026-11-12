#ifndef __BPF_ENDIAN_H
#define __BPF_ENDIAN_H

#include "linux_types.h"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_cpu_to_be64(x) __builtin_bswap64(x)
#define bpf_be64_to_cpu(x) __builtin_bswap64(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_htonl(x) (x)
#define bpf_ntohl(x) (x)
#define bpf_cpu_to_be64(x) (x)
#define bpf_be64_to_cpu(x) (x)
#else
#error "Byte order cannot be determined"
#endif

#endif /* __BPF_ENDIAN_H */

