#include "eaglevm-core/virtual_machine/machines/owl/loader.h"

#include "eaglevm-core/codec/zydis_helper.h"
#include "eaglevm-core/util/assert.h"
#include "eaglevm-core/util/random.h"

using namespace eagle::codec;
using namespace eagle::codec::encoder;

namespace eagle::virt::owl
{
    void register_loader::load_register(const reg register_to_load, const reg load_destination,
        encoder::encode_builder& out) const
    {
        VM_ASSERT(get_reg_class(load_destination) == gpr_64, "invalid size of load destination");
        const reg target_register = load_destination;

        // find the mapped ranges required to build the register that we want
        // shuffle the ranges because we will rebuild it at random
        std::vector<reg_mapped_range> ranges_required = get_relevant_ranges(register_to_load);
        trim_ranges(ranges_required, register_to_load);

        if (is_upper_8(register_to_load))
        {
            for (reg_mapped_range& mapping : ranges_required)
            {
                auto& [source_range,dest_range, dest_reg] = mapping;
                auto& [s_from, s_to] = source_range;

                s_from -= 8;
                s_to -= 8;
            }
        }

        std::ranges::shuffle(ranges_required, util::ran_device::get().gen);
        load_register_internal(target_register, ranges_required, out);
    }

    void register_loader::load_register_internal(reg load_destination, const std::vector<reg_mapped_range>& ranges_required,
        encoder::encode_builder& out) const
    {
        out.make(m_xor, reg_op(load_destination), reg_op(load_destination));

        std::vector<reg_range> stored_ranges;
        for (const reg_mapped_range& mapping : ranges_required)
        {
            const auto& [source_range,dest_range, source_register] = mapping;
            auto [destination_start, destination_end] = source_range;
            auto [source_start, source_end] = dest_range;

            scope_register_manager int_64_ctx = regs_64_context->create_scope();
            if (get_reg_class(source_register) == xmm_128)
            {
                if (source_end <= 64) // lower 64 bits of XMM
                {
                    /*
                        gpr_temp = fun_get_temps()[0];

                        movq gpr_temp, source_register // move lower 64 bits into temp
                        shl gpr_temp, 64 - source_end	// clear upper end bits
                        shr gpr_temp, 64 - source_end + source_start	// clear lower start bits
                        shl gpr_temp, destination_start	// move to intended destination location
                        or target_register, get_bit_version(gpr_temp, bit_64)	// write bits to target
                     */

                    reg gpr_temp = int_64_ctx.reserve();
                    out.make(m_movq, reg_op(gpr_temp), reg_op(source_register))
                       .make(m_shl, reg_op(gpr_temp), imm_op(64 - source_end))
                       .make(m_shr, reg_op(gpr_temp), imm_op(64 - source_end + source_start))
                       .make(m_shl, reg_op(gpr_temp), imm_op(destination_start))
                       .make(m_or, reg_op(load_destination), reg_op(gpr_temp));
                }
                else if (source_start >= 64) // upper 64 bits of XMM
                {
                    /*
                        psrldq source_register, 8	// move upper 64 bits to lower 64 bits

                        source_start -= 64	// since we shifted down it will be 64 bits lower
                        source_end -= 64	// since we shifted down it will be 64 bits lower

                        gpr_temp = fun_get_temps()[0];

                        movq gpr_temp, source_register // move lower 64 bits into temp
                        shl gpr_temp, 64 - source_end	// clear upper end bits
                        shr gpr_temp, 64 - source_end + source_start	// clear lower start bits
                        shl gpr_temp, destination_start	// move to intended destination location
                        or target_register, get_bit_version(gpr_temp, bit_64)	// write bits to target

                        psrldq source_register, 8	// move lower 64 bits back to upper 64 bits
                    */


                    source_start -= 64;
                    source_end -= 64;

                    reg gpr_temp = int_64_ctx.reserve();
                    out.make(m_pextrq, reg_op(gpr_temp), reg_op(source_register), imm_op(1))
                       .make(m_shl, reg_op(gpr_temp), imm_op(64 - source_end))
                       .make(m_shr, reg_op(gpr_temp), imm_op(64 - source_end + source_start))
                       .make(m_shl, reg_op(gpr_temp), imm_op(destination_start))
                       .make(m_or, reg_op(load_destination), reg_op(gpr_temp));
                }
                else // cross boundary register
                {
                    /*
                        // lower boundary
                        // [source_start, 64)

                        temps = fun_get_temps(2);
                        gpr_temp = temps[0];

                        movq gpr_temp, source_register // move lower 64 bits into temp
                        shr gpr_temp, 64 - source_start	// clear lower start bits
                        shl gpr_temp, destination_start	// move to intended destination location
                        or target_register, get_bit_version(gpr_temp, bit_64)	// write bits to target

                        // upper boundary
                        // [64, source_end)

                        psrldq source_register, 8	// move upper 64 bits to lower 64 bits

                        source_start = 0	// because we read across boundaries this will now start at 0
                        source_end -= 64	// since we shifted down it will be 64 bits lower

                        gpr_temp = temps[1];

                        movq gpr_temp, source_register // move lower 64 bits into temp
                        shl gpr_temp, 64 - source_end	// clear upper end bits
                        shr gpr_temp, 64 - source_end	// move to intended destination location
                        or target_register, get_bit_version(gpr_temp, bit_64)	// write bits to target

                        psrldq source_register, 8	// move lower 64 bits back to upper 64 bits
                    */

                    // reg gpr_temp = temp_regs[0];
                    // out->add({
                    //     encode(m_movq, reg_op(gpr_temp), reg_op(source_register)),
                    //     encode(m_shr, reg_op(gpr_temp), imm_op(64 - source_start)),
                    //     encode(m_shl, reg_op(gpr_temp), imm_op(destination_start)),
                    //     encode(m_or, reg_op(target_register), reg_op(gpr_temp))
                    // });

                    // source_start = 0;
                    // source_end -= 64;

                    // gpr_temp = temp_regs[1];
                    // out->add({
                    //     encode(m_pextrq, reg_op(gpr_temp), reg_op(source_register), imm_op(1)),
                    //     encode(m_movq, reg_op(gpr_temp), reg_op(source_register)),
                    //     encode(m_shl, reg_op(gpr_temp), imm_op(64 - source_end)),
                    //     encode(m_shr, reg_op(gpr_temp), imm_op(64 - source_end)),
                    //     encode(m_or, reg_op(target_register), reg_op(gpr_temp)),
                    // });

                    VM_ASSERT("this should not happen as the register manager should handle cross boundary loads");
                }
            }
            else
            {
                /*
                    gpr_temp = fun_get_temps()[0];

                    mov gpr_temp, source_register // move lower 64 bits into temp
                    shl gpr_temp, 64 - source_end	// clear upper end bits
                    shr gpr_temp, 64 - source_end + source_start	// clear lower start bits
                    shl gpr_temp, destination_start	// move to intended destination location
                    or target_register, get_bit_version(gpr_temp, bit_64)	// write bits to target
                */

                reg gpr_temp = int_64_ctx.reserve();
                out.make(m_mov, reg_op(gpr_temp), reg_op(source_register))
                   .make(m_shl, reg_op(gpr_temp), imm_op(64 - source_end))
                   .make(m_shr, reg_op(gpr_temp), imm_op(64 - source_end + source_start))
                   .make(m_shl, reg_op(gpr_temp), imm_op(destination_start))
                   .make(m_or, reg_op(load_destination), reg_op(gpr_temp));
            }

            stored_ranges.push_back(source_range);
        }
    }

    void register_loader::store_register(const reg register_to_store_into, const reg source, encoder::encode_builder& out) const
    {
        VM_ASSERT(get_reg_class(source) == gpr_64, "invalid size of load destination");

        // find the mapped ranges required to build the register that we want
        // shuffle the ranges because we will rebuild it at random
        std::vector<reg_mapped_range> ranges_required = get_relevant_ranges(register_to_store_into);
        trim_ranges(ranges_required, register_to_store_into);

        if (is_upper_8(register_to_store_into))
        {
            for (reg_mapped_range& mapping : ranges_required)
            {
                auto& [source_range,dest_range, dest_reg] = mapping;
                auto& [s_from, s_to] = source_range;

                s_from -= 8;
                s_to -= 8;
            }
        }

        std::ranges::shuffle(ranges_required, util::ran_device::get().gen);
        store_register_internal(source, ranges_required, out);
    }

    void register_loader::store_register_internal(reg source_register, const std::vector<reg_mapped_range>& ranges_required,
        encoder::encode_builder& out) const
    {
        std::vector<reg_range> stored_ranges;
        for (const reg_mapped_range& mapping : ranges_required)
        {
            const auto& [source_range,dest_range, dest_reg] = mapping;

            // this is the bit ranges that will be in our source
            auto [s_from, s_to] = source_range;
            auto [d_from, d_to] = dest_range;

            auto scope_64 = regs_64_context->create_scope();

            const reg_class dest_reg_class = get_reg_class(dest_reg);
            if (dest_reg_class == gpr_64)
            {
                // gpr
                reg temp_value_reg = scope_64.reserve();
                out.make(m_mov, reg_op(temp_value_reg), reg_op(source_register))
                   .make(m_shl, reg_op(temp_value_reg), imm_op(64 - s_to))
                   .make(m_shr, reg_op(temp_value_reg), imm_op(s_from + 64 - s_to));

                const uint8_t bit_length = s_to - s_from;

                reg temp_xmm_q = scope_64.reserve();
                out.make(m_mov, reg_op(temp_xmm_q), reg_op(dest_reg))
                   .make(m_ror, reg_op(temp_xmm_q), imm_op(d_from))
                   .make(m_shr, reg_op(temp_xmm_q), imm_op(bit_length))
                   .make(m_shl, reg_op(temp_xmm_q), imm_op(bit_length))
                   .make(m_or, reg_op(temp_xmm_q), reg_op(temp_value_reg))
                   .make(m_rol, reg_op(temp_xmm_q), imm_op(d_from))
                   .make(m_mov, reg_op(dest_reg), reg_op(temp_xmm_q));
            }
            else
            {
                // xmm0

                /*
                 * step 1: setup vtemp register
                 *
                 * mov vtemp, src
                 * shl vtemp, 64 - s_to
                 * shr vtemp, s_from + 64 - s_to
                 */

                reg temp_value = scope_64.reserve();
                out.make(m_mov, reg_op(temp_value), reg_op(source_register))
                   .make(m_shl, reg_op(temp_value), imm_op(64 - s_to))
                   .make(m_shr, reg_op(temp_value), imm_op(s_from + 64 - s_to));

                /*
                 * step 2: clear and store
                 * this is where things get complicated
                 *
                 * im pretty certain there is no SSE instruction to shift bits in an XMM register
                 * but there is one to shift bytes which really really sucks
                 */

                auto handle_lb = [&](auto to, auto from, auto temp_value_reg)
                {
                    reg temp_xmm_q = scope_64.reserve();
                    const uint8_t bit_length = to - from;

                    out.make(m_movq, reg_op(temp_xmm_q), reg_op(dest_reg))
                       .make(m_ror, reg_op(temp_xmm_q), imm_op(from))
                       .make(m_shr, reg_op(temp_xmm_q), imm_op(bit_length))
                       .make(m_shl, reg_op(temp_xmm_q), imm_op(bit_length))
                       .make(m_or, reg_op(temp_xmm_q), reg_op(temp_value_reg))
                       .make(m_rol, reg_op(temp_xmm_q), imm_op(from))
                       .make(m_pinsrq, reg_op(dest_reg), reg_op(temp_xmm_q), imm_op(0));
                };

                auto handle_ub = [&](auto to, auto from, auto temp_value_reg)
                {
                    reg temp_xmm_q = scope_64.reserve();
                    const uint8_t bit_length = to - from;

                    out.make(m_pextrq, reg_op(temp_xmm_q), reg_op(dest_reg), imm_op(1))
                       .make(m_ror, reg_op(temp_xmm_q), imm_op(from - 64))
                       .make(m_shr, reg_op(temp_xmm_q), imm_op(bit_length))
                       .make(m_shl, reg_op(temp_xmm_q), imm_op(bit_length))
                       .make(m_or, reg_op(temp_xmm_q), reg_op(temp_value_reg))
                       .make(m_rol, reg_op(temp_xmm_q), imm_op(from - 64))
                       .make(m_pinsrq, reg_op(dest_reg), reg_op(temp_xmm_q), imm_op(1));
                };

                // case 1: all the bits are located in qword 1
                // solution is simple: movq
                if (d_to <= 64)
                    handle_lb(d_to, d_from, temp_value);

                    // case 2: all bits are located in qword 2
                    // solution is simple: rotate qwords read bottom one
                else if (d_from >= 64)
                    handle_ub(d_to, d_from, temp_value);
                    // case 3: we have a boundary, fuck
                else
                    VM_ASSERT("this should not happen, register manager needs to split cross boundary reads");
            }
        }
    }

    void register_loader::trim_ranges(std::vector<reg_mapped_range>& ranges_required, const reg target)
    {
        uint16_t significant_start = 0;
        uint16_t significant_end = get_reg_size(target);

        if (is_upper_8(target))
        {
            significant_start += 8;
            significant_end += 8;
        }

        for (auto& [source_range, dest_range, dest_reg] : ranges_required)
        {
            auto [ds, de] = dest_range;
            auto [ss, se] = source_range;

            const uint16_t overlap_start = std::max(ss, significant_start);
            const uint16_t overlap_end = std::min(se, significant_end);

            if (overlap_start < overlap_end)
            {
                // There is an overlap, adjust the ranges
                const uint16_t shift = overlap_start - ss;

                // Adjust destination range
                dest_range.first = ds + shift;
                dest_range.second = dest_range.first + (overlap_end - overlap_start);

                // Adjust source range
                source_range.first = overlap_start;
                source_range.second = overlap_end;
            }
        }
    }

    std::vector<reg_mapped_range> register_loader::get_relevant_ranges(const reg source_reg) const
    {
        const std::vector<reg_mapped_range> mappings = regs->get_register_mapped_ranges(get_bit_version(source_reg, bit_64));

        uint16_t min_bit = 0;
        uint16_t max_bit = get_reg_size(source_reg);

        if (is_upper_8(source_reg))
        {
            min_bit = 8;
            max_bit = 16;
        }

        std::vector<reg_mapped_range> ranges_required;
        for (const auto& mapping : mappings)
        {
            const auto& [source_range, _, _1] = mapping;

            const uint16_t start = std::get<0>(source_range);
            const uint16_t end = std::get<1>(source_range);
            if (std::max(start, min_bit) <= std::min(end, max_bit))
                ranges_required.push_back(mapping);
        }

        return ranges_required;
    }
}
