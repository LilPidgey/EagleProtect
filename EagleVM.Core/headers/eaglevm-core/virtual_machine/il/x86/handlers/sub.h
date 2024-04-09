#pragma once
#include "eaglevm-core/virtual_machine/il/x86/base_handler_gen.h"
#include "eaglevm-core/virtual_machine/il/x86/base_x86_lifter.h"

namespace eagle::il::handler
{
    class sub : public base_handler_gen
    {
    public:
        sub();
        il_insts gen_handler(codec::reg_class size, uint8_t operands) override;
    };
}

namespace eagle::il::lifter
{
    class sub : public base_x86_lifter
    {
    };
}