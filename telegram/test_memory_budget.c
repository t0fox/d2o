#include "tg_memory_budget.h"

#include <assert.h>
#include <stdio.h>

static void test_dynamic_buffer_budget_is_hard_and_releasable(void) {
    tg_memory_budget budget = {.limit = 64u * 1024u};

    assert(tg_memory_budget_reserve(&budget, 48u * 1024u) == 0);
    assert(budget.used == 48u * 1024u);
    assert(budget.peak == budget.used);
    assert(tg_memory_budget_reserve(&budget, 16u * 1024u + 1u) != 0);
    assert(budget.used == 48u * 1024u);
    assert(tg_memory_budget_reserve(&budget, 16u * 1024u) == 0);
    assert(budget.used == budget.limit && budget.peak == budget.limit);

    tg_memory_budget_release(&budget, 32u * 1024u);
    assert(budget.used == 32u * 1024u);
    assert(tg_memory_budget_reserve(&budget, 32u * 1024u) == 0);
    assert(budget.used == budget.limit && budget.peak == budget.limit);
    tg_memory_budget_release(&budget, budget.limit);
    assert(budget.used == 0);
}

int main(void) {
    test_dynamic_buffer_budget_is_hard_and_releasable();
    puts("Тест динамического бюджета Telegram: ок");
    return 0;
}
