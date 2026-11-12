#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "secure_alloc.h"

#include <stdint.h>
#include <string.h>

#include "monocypher.h"

#ifdef _WIN32
#include <windows.h>
#elif defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#endif

static size_t round_up_to_page_size(size_t size, size_t page_size) {
  const size_t remainder = size % page_size;
  if (remainder == 0) {
    return size;
  }
  const size_t padding = page_size - remainder;
  if (size > SIZE_MAX - padding) {
    return 0;
  }
  return size + padding;
}

secure_alloc_result_t allocate_secure_memory(size_t requested_size,
                                             secure_alloc_t* alloc) {
  if (alloc == NULL || requested_size == 0) {
    return SECURE_ALLOC_INVALID_SIZE;
  }
  alloc->data = NULL;
  alloc->requested_size = 0;
  alloc->mapped_size = 0;

#ifdef _WIN32
  SYSTEM_INFO system_info;
  GetSystemInfo(&system_info);
  const size_t page_size = system_info.dwPageSize;
#elif defined(__linux__)
  const long system_page_size = sysconf(_SC_PAGESIZE);
  if (system_page_size <= 0) {
    return SECURE_ALLOC_PAGE_SIZE_FAILED;
  }
  const size_t page_size = (size_t)system_page_size;
#else
  return SECURE_ALLOC_UNSUPPORTED;
#endif

  if (page_size == 0) {
    return SECURE_ALLOC_PAGE_SIZE_FAILED;
  }
  const size_t mapped_size = round_up_to_page_size(requested_size, page_size);
  if (mapped_size == 0) {
    return SECURE_ALLOC_INVALID_SIZE;
  }

#ifdef _WIN32
  void* memory = VirtualAlloc(NULL, mapped_size, MEM_RESERVE | MEM_COMMIT,
                              PAGE_READWRITE);
  if (memory == NULL) {
    return SECURE_ALLOC_MAPPING_FAILED;
  }
  if (!VirtualLock(memory, mapped_size)) {
    VirtualFree(memory, 0, MEM_RELEASE);
    return SECURE_ALLOC_LOCK_FAILED;
  }
#elif defined(__linux__)
  void* memory = mmap(NULL, mapped_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (memory == MAP_FAILED) {
    return SECURE_ALLOC_MAPPING_FAILED;
  }
  if (mlock(memory, mapped_size) != 0) {
    munmap(memory, mapped_size);
    return SECURE_ALLOC_LOCK_FAILED;
  }
#if defined(MADV_DONTDUMP)
  if (madvise(memory, mapped_size, MADV_DONTDUMP) != 0) {
    crypto_wipe(memory, mapped_size);
    munlock(memory, mapped_size);
    munmap(memory, mapped_size);
    return SECURE_ALLOC_DONTDUMP_FAILED;
  }
#else
  crypto_wipe(memory, mapped_size);
  munlock(memory, mapped_size);
  munmap(memory, mapped_size);
  return SECURE_ALLOC_UNSUPPORTED;
#endif
#endif

  alloc->data = (uint8_t*)memory;
  alloc->requested_size = requested_size;
  alloc->mapped_size = mapped_size;
  return SECURE_ALLOC_OK;
}

void clear_secure_memory(secure_alloc_t* alloc) {
  if (alloc == NULL) {
    return;
  }

  if (alloc->data != NULL) {
    crypto_wipe(alloc->data, alloc->mapped_size);
#ifdef _WIN32
    VirtualUnlock(alloc->data, alloc->mapped_size);
    VirtualFree(alloc->data, 0, MEM_RELEASE);
#elif defined(__linux__)
    munlock(alloc->data, alloc->mapped_size);
    munmap(alloc->data, alloc->mapped_size);
#endif
  }
  memset(alloc, 0, sizeof(*alloc));
}
