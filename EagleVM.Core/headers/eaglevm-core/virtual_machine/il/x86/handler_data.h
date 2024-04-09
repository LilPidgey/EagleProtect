#pragma once
#include <unordered_map>
#include "eaglevm-core/codec/zydis_helper.h"
#include "eaglevm-core/virtual_machine/il/x86/base_handler_gen.h"
#include "eaglevm-core/virtual_machine/il/x86/handler_include.h"

namespace eagle::il
{
    extern std::unordered_map<codec::mnemonic, std::shared_ptr<handler::base_handler_gen>> instruction_handlers;
}