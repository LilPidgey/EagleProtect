#pragma once
#include "eaglevm-core/virtual_machine/ir/x86/base_handler_gen.h"
#include "eaglevm-core/virtual_machine/ir/x86/base_x86_translator.h"

namespace eagle::il::handler
{
    class pop : public base_handler_gen
    {
    public:
        pop();
        ir_insts gen_handler(codec::reg_class size, uint8_t operands) override;
    };
}

namespace eagle::il::lifter
{
    class pop : public base_x86_translator
    {
        using base_x86_translator::base_x86_translator;
    };
}