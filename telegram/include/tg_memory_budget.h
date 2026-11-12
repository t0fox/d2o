#ifndef D2K_TG_MEMORY_BUDGET_H
#define D2K_TG_MEMORY_BUDGET_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t limit;
    size_t used;
    size_t peak;
    uint64_t rejections;
    uint64_t allocation_failures;
    uint64_t size_rejections;
} tg_memory_budget;

int tg_memory_budget_reserve(tg_memory_budget *budget, size_t bytes);
void tg_memory_budget_release(tg_memory_budget *budget, size_t bytes);

#endif
