﻿#include "virtual_machine/vm_register_manager.h"

void vm_register_manager::init_reg_order()
{
    for (int i = ZYDIS_REGISTER_RAX; i <= ZYDIS_REGISTER_R15; i++)
        reg_stack_order_[i - ZYDIS_REGISTER_RAX] = (zydis_register)i;

    auto rng = std::default_random_engine{};
    std::ranges::shuffle(reg_stack_order_, rng);
}

std::pair<uint32_t, uint16_t> vm_register_manager::get_stack_displacement(zydis_register reg)
{
    //determine 64bit version of register
    auto reg_size = zydis_helper::get_reg_size(reg);

    int current_index = 0;
    std::ranges::for_each(reg_stack_order_, [this, &current_index](zydis_register reg)
        {
            if (reg == reg_stack_order_[current_index])
                return false;

            current_index++;
            return true;
        });

    return {(current_index * 8) + (8 - reg_size), reg_size};
}

void vm_register_manager::set_reg_mapping(const short index, const zydis_register reg)
{
    reg_map[index] = reg;
}

bool vm_register_manager::contains_reg_mapping(short mapping, zydis_register reg)
{
    return std::ranges::any_of(reg_map,
            [reg](const zydis_register register_)
                {
                    return register_ == reg;
                });
}
