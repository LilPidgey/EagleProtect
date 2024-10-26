#include "eaglevm-core/virtual_machine/ir/x86/handlers/sub.h"
#include "eaglevm-core/virtual_machine/ir/x86/handlers/util/flags.h"

#include "eaglevm-core/virtual_machine/ir/commands/cmd_context_rflags_load.h"
#include "eaglevm-core/virtual_machine/ir/commands/cmd_context_rflags_store.h"

namespace eagle::ir::handler
{
    sub::sub()
    {
        valid_operands = {
            { { { codec::op_none, codec::bit_8 }, { codec::op_none, codec::bit_8 } }, "sub 8,8" },
            { { { codec::op_none, codec::bit_16 }, { codec::op_none, codec::bit_16 } }, "sub 16,16" },
            { { { codec::op_none, codec::bit_32 }, { codec::op_none, codec::bit_32 } }, "sub 32,32" },
            { { { codec::op_none, codec::bit_64 }, { codec::op_none, codec::bit_64 } }, "sub 64,64" },

            // sign extended handlers
            { { { codec::op_none, codec::bit_16 }, { codec::op_imm, codec::bit_8 } }, "sub 16,16" },
            { { { codec::op_none, codec::bit_32 }, { codec::op_imm, codec::bit_8 } }, "sub 32,32" },
            { { { codec::op_none, codec::bit_64 }, { codec::op_imm, codec::bit_8 } }, "sub 64,64" },
            { { { codec::op_none, codec::bit_64 }, { codec::op_imm, codec::bit_32 } }, "sub 64,64" },
        };

        build_options = {
            { { ir_size::bit_8, ir_size::bit_8 }, "sub 8,8" },
            { { ir_size::bit_16, ir_size::bit_16 }, "sub 16,16" },
            { { ir_size::bit_32, ir_size::bit_32 }, "sub 32,32" },
            { { ir_size::bit_64, ir_size::bit_64 }, "sub 64,64" },
        };
    }

    ir_insts sub::gen_handler(const handler_sig signature)
    {
        VM_ASSERT(signature.size() == 2, "invalid signature. must contain 2 operands");
        VM_ASSERT(signature[0] == signature[1], "invalid signature. must contain same sized parameters");

        ir_size target_size = signature.front();

        const discrete_store_ptr p_one = discrete_store::create(target_size);
        const discrete_store_ptr p_two = discrete_store::create(target_size);
        const discrete_store_ptr result = discrete_store::create(target_size);

        const discrete_store_ptr flags_result = discrete_store::create(ir_size::bit_64);

        // todo: some kind of virtual machine implementation where it could potentially try to optimize a pop and use of the register in the next
        // instruction using stack dereference
        constexpr auto affected_flags = ZYDIS_CPUFLAG_OF | ZYDIS_CPUFLAG_SF | ZYDIS_CPUFLAG_ZF | ZYDIS_CPUFLAG_AF | ZYDIS_CPUFLAG_PF |
            ZYDIS_CPUFLAG_CF;
        ir_insts insts = {
            std::make_shared<cmd_sub>(target_size, false, true),

            // The OF, SF, ZF, AF, PF, and CF flags are set according to the result.
            std::make_shared<cmd_context_rflags_load>(),
            std::make_shared<cmd_push>(~affected_flags, ir_size::bit_64),
            std::make_shared<cmd_and>(ir_size::bit_64),
        };

        insts.append_range(compute_of(target_size, result, p_two, p_one, flags_result));
        insts.append_range(compute_af(target_size, result, p_two, p_one, flags_result));
        insts.append_range(compute_cf(target_size, result, p_two, p_one, flags_result));

        insts.append_range(util::calculate_sf(target_size, result));
        insts.append_range(util::calculate_zf(target_size, result));
        insts.append_range(util::calculate_pf(target_size, result));

        return insts;
    }

    ir_insts sub::compute_of(ir_size size, const discrete_store_ptr& result, const discrete_store_ptr& p_one, const discrete_store_ptr& p_two,
        const discrete_store_ptr& flags)
    {
        // a_sign == b_sign AND r_sign == b_sign

        // r_sign XOR b_sign
        ir_insts insts;
        {
            insts.append_range(copy_to_top(size, util::result));
            insts.append_range(ir_insts{
                // r_sign = r >> (size - 1) & 1
                std::make_shared<cmd_push>(static_cast<uint64_t>(size) - 1, size),
                std::make_shared<cmd_shr>(size),
                std::make_shared<cmd_push>(1, size),
                std::make_shared<cmd_and>(size),
            });

            insts.append_range(copy_to_top(size, util::param_two, { size }));
            insts.append_range(ir_insts{
                // b_sign = b >> (size - 1) & 1
                std::make_shared<cmd_push>(static_cast<uint64_t>(size) - 1, size),
                std::make_shared<cmd_shr>(size),
                std::make_shared<cmd_push>(1, size),
                std::make_shared<cmd_and>(size),
            });

            insts.push_back(std::make_shared<cmd_xor>(size));
        }

        // b_sign XOR a_sign
        {
            insts.append_range(copy_to_top(size, util::param_two, { size }));
            insts.append_range(ir_insts{
                // b_sign = b >> (size - 1) & 1
                std::make_shared<cmd_push>(static_cast<uint64_t>(size) - 1, size),
                std::make_shared<cmd_shr>(size),
                std::make_shared<cmd_push>(1, size),
                std::make_shared<cmd_and>(size),
            });

            insts.append_range(copy_to_top(size, util::param_one, { size, size }));
            insts.append_range(ir_insts{
                // a_sign = a >> (size - 1) & 1
                std::make_shared<cmd_push>(static_cast<uint64_t>(size) - 1, size),
                std::make_shared<cmd_shr>(size),
                std::make_shared<cmd_push>(1, size),
                std::make_shared<cmd_and>(size),
            });

            insts.push_back(std::make_shared<cmd_xor>(size));
        }

        insts.append_range(ir_insts{
            // (r_sign XOR b_sign) OR (b_sign XOR a_sign)
            std::make_shared<cmd_or>(size),

            // OF = (r_sign XOR b_sign) OR (b_sign XOR a_sign)
            std::make_shared<cmd_resize>(ir_size::bit_64, size),
            std::make_shared<cmd_push>(util::flag_index(ZYDIS_CPUFLAG_OF), ir_size::bit_64),
            std::make_shared<cmd_shl>(ir_size::bit_64),
            std::make_shared<cmd_or>(ir_size::bit_64),
        });

        return insts;
    }

    ir_insts sub::compute_af(ir_size size, const discrete_store_ptr& result, const discrete_store_ptr& p_one, const discrete_store_ptr& p_two,
        const discrete_store_ptr& flags)
    {
        //
        // AF = ((A & 0xF) + (B & 0xF) >> 4) & 1
        //
        ir_insts insts;

        insts.append_range(copy_to_top(size, util::param_one));
        insts.append_range(ir_insts{
            std::make_shared<cmd_push>(0xF, size),
            std::make_shared<cmd_and>(size),
        });

        insts.append_range(copy_to_top(size, util::param_two, { size }));
        insts.append_range(ir_insts{
            std::make_shared<cmd_push>(0xF, size),
            std::make_shared<cmd_and>(size),
        });

        // (() + () >> 4) & 1
        insts.append_range(ir_insts{
            std::make_shared<cmd_add>(size),
            std::make_shared<cmd_push>(4, size),
            std::make_shared<cmd_shr>(size),

            std::make_shared<cmd_push>(1, size),
            std::make_shared<cmd_and>(size),

            // AF = ((A & 0xF) + (B & 0xF) >> 4) & 1
            std::make_shared<cmd_resize>(ir_size::bit_64, size),
            std::make_shared<cmd_push>(util::flag_index(ZYDIS_CPUFLAG_AF), ir_size::bit_64),
            std::make_shared<cmd_shl>(ir_size::bit_64),
            std::make_shared<cmd_or>(ir_size::bit_64),
        });

        return insts;
    }

    ir_insts sub::compute_cf(ir_size size, const discrete_store_ptr& result, const discrete_store_ptr& p_one, const discrete_store_ptr& p_two,
        const discrete_store_ptr& flags)
    {
        //
        // CF = ((A & B) | ((A | B) & ~R)) >> 63
        //

        return {
            std::make_shared<cmd_push>(p_one, ir_size::bit_64),

            // ((A | B) & ~R)
            make_dyn(codec::m_or, encoder::reg(p_one), encoder::reg(p_two)),
            make_dyn(codec::m_not, encoder::reg(result)),
            make_dyn(codec::m_and, encoder::reg(result), encoder::reg(p_one)),

            std::make_shared<cmd_pop>(p_one, ir_size::bit_64),

            // (A & B)
            make_dyn(codec::m_and, encoder::reg(p_one), encoder::reg(p_two)),
            make_dyn(codec::m_or, encoder::reg(p_one), encoder::reg(result)),

            // >> 63
            make_dyn(codec::m_shr, encoder::reg(p_one), encoder::imm(63)),
        };
    }
}

namespace eagle::ir::lifter
{
    translate_mem_result sub::translate_mem_action(const codec::dec::op_mem& op_mem, uint8_t idx)
    {
        return idx == 0 ? translate_mem_result::both : base_x86_translator::translate_mem_action(op_mem, idx);
    }

    translate_status sub::encode_operand(codec::dec::op_imm op_imm, uint8_t)
    {
        codec::dec::operand second_op = operands[1];
        codec::dec::operand first_op = operands[0];

        ir_size imm_size = static_cast<ir_size>(second_op.size);
        ir_size imm_size_target = static_cast<ir_size>(first_op.size);

        block->push_back(std::make_shared<cmd_push>(op_imm.value.u, imm_size));
        if (imm_size != imm_size_target)
            block->push_back(std::make_shared<cmd_sx>(imm_size_target, imm_size));

        return translate_status::success;
    }

    void sub::finalize_translate_to_virtual(x86_cpu_flag flags)
    {
        base_x86_translator::finalize_translate_to_virtual(flags);

        codec::dec::operand first_op = operands[0];
        if (first_op.type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            // register
            codec::reg reg = static_cast<codec::reg>(first_op.reg.value);
            if (static_cast<ir_size>(first_op.size) == ir_size::bit_32)
                reg = codec::get_bit_version(first_op.reg.value, codec::gpr_64);

            block->push_back(std::make_shared<cmd_context_store>(reg, static_cast<codec::reg_size>(first_op.size)));
        }
        else if (first_op.type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            ir_size value_size = static_cast<ir_size>(first_op.size);
            block->push_back(std::make_shared<cmd_mem_write>(value_size, value_size));
        }
    }
}
