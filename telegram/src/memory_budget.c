#include "tg_memory_budget.h"

#include <errno.h>

int tg_memory_budget_reserve(tg_memory_budget *budget, size_t bytes) {
    if (!budget || budget->used > budget->limit ||
        bytes > budget->limit - budget->used) {
        errno = ENOMEM;
        return -1;
    }
    budget->used += bytes;
    if (budget->used > budget->peak) budget->peak = budget->used;
    return 0;
}

void tg_memory_budget_release(tg_memory_budget *budget, size_t bytes) {
    if (!budget) return;
    budget->used = bytes > budget->used ? 0 : budget->used - bytes;
}
