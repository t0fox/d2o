#ifndef D2K_TG_MEMORY_BUDGET_H
#define D2K_TG_MEMORY_BUDGET_H

#include <stddef.h>

typedef struct {
    size_t limit;
    size_t used;
    size_t peak;
} tg_memory_budget;

int tg_memory_budget_reserve(tg_memory_budget *budget, size_t bytes);
void tg_memory_budget_release(tg_memory_budget *budget, size_t bytes);

#endif
