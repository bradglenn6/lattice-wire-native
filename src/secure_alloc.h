#ifndef LATTICE_SECURE_ALLOC_H
#define LATTICE_SECURE_ALLOC_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint8_t* data;
  size_t requested_size;
  size_t mapped_size;
} secure_alloc_t;

typedef enum {
  SECURE_ALLOC_OK,
  SECURE_ALLOC_INVALID_SIZE,
  SECURE_ALLOC_PAGE_SIZE_FAILED,
  SECURE_ALLOC_MAPPING_FAILED,
  SECURE_ALLOC_LOCK_FAILED,
  SECURE_ALLOC_DONTDUMP_FAILED,
  SECURE_ALLOC_UNSUPPORTED
} secure_alloc_result_t;

#ifdef __cplusplus
extern "C" {
#endif

secure_alloc_result_t allocate_secure_memory(size_t requested_size,
                                             secure_alloc_t* alloc);
void clear_secure_memory(secure_alloc_t* alloc);

#ifdef __cplusplus
}
#endif

#endif
