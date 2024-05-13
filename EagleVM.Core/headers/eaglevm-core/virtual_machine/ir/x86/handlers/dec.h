#pragma once
#include "eaglevm-core/virtual_machine/ir/x86/base_handler_gen.h"
#include "eaglevm-core/virtual_machine/ir/x86/base_x86_translator.h"

namespace eagle::il::handler
{
    class dec : public base_handler_gen
    {
    public:
        dec();
        ir_insts gen_handler(codec::reg_class size, uint8_t operands) override;
    };
}

namespace eagle::il::lifter
{
    class dec : public base_x86_translator
    {
        using base_x86_translator::base_x86_translator;
        void finalize_translate_to_virtual() override;
    };
}
