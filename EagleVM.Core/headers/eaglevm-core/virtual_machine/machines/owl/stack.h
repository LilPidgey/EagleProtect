#pragma once
#pragma once
#include "eaglevm-core/virtual_machine/machines/owl/register_manager.h"
#include "eaglevm-core/compiler/code_container.h"
#include "eaglevm-core/util/random.h"
#include "eaglevm-core/virtual_machine/machines/register_context.h"
#include "eaglevm-core/virtual_machine/machines/eagle/register_manager.h"

namespace eagle::virt::owl
{
    inline register_manager_ptr reg_man;
    inline register_context_ptr reg_64_container;
    inline register_context_ptr reg_256_container;
    inline settings_ptr settings;

    using namespace codec;
    using namespace codec::encoder;

    inline void gen_vsp_modification(encode_builder& out, const bool sub)
    {
        scope_register_manager ymm_context = reg_256_container->create_scope();
        const auto temp = ymm_context.reserve();
        const auto adder = ymm_context.reserve();

        scope_register_manager gpr_scope = reg_64_container->create_scope();
        const auto gpr_adder = gpr_scope.reserve();

        auto build_mov_mask = [&](const uint8_t start_bit, const bool allow_random = true) -> uint8_t
        {
            VM_ASSERT(start_bit % 8 == 0, "for now we only want aligned");
            const uint8_t target_lane = start_bit / 8;

            uint8_t out_mask = 0;
            if (settings->random_kmask && allow_random) // some bool to check if we want to generate garbage masks
                out_mask = util::get_ran_device().gen_8();

            return 1 << target_lane | out_mask;
        };

        // i know you can do this by just doing an add/sub on the vsp_reg lane, but this is just abstracted
        // to allow for better obfuscation and when VSP wont just be a single qword inside one lane
        auto [vsp_reg, vsp_lane] = reg_man->get_vsp_map();
        out
            .make(m_kmovb, reg_op(k1), imm_op(build_mov_mask(vsp_lane)))
            .make(m_vmovdqu64, reg_op(temp), reg_op(k1), reg_op(vsp_reg)) // mov VSP into our temp reg
            .make(m_mov, reg_op(gpr_adder), imm_op(8))
            .make(m_vpbroadcastq, reg_op(adder), reg_op(gpr_adder))
            .make(sub ? m_vpsubq : m_vpaddq, reg_op(temp), reg_op(adder))
            .make(m_kmovb, reg_op(k1), imm_op(build_mov_mask(vsp_lane, false)))
            .make(m_vmovdqu64, reg_op(vsp_reg), reg_op(k1), reg_op(temp));
    }

    inline void sub_vsp(encode_builder& out)
    {
        gen_vsp_modification(out, true);
    }

    inline void add_vsp(encode_builder& out)
    {
        gen_vsp_modification(out, false);
    }

    void push_64(const reg input_reg, encode_builder& out)
    {
        scope_register_manager ymm_context = reg_256_container->create_scope();
        const auto ymm_bound = ymm_context.reserve();
        const auto ymm_vsp = ymm_context.reserve();
        const auto ymm_cmp = ymm_vsp;
        const auto ymm_broad_value = ymm_vsp;

        scope_register_manager gpr_scope = reg_64_container->create_scope();
        const reg vsp = gpr_scope.reserve();
        const reg mask_holder = vsp;
        const reg lane_holder = mask_holder;

        auto [vsp_ymm, vsp_lane] = reg_man->get_vsp_map();
        const auto vsp_xmm = get_bit_version(vsp_ymm, bit_128); // get the xmm

        if (vsp_lane != 0)
        {
            auto move_mask = 0b'11'10'10'00;

            // we want to swap whatever vsp_lane and 0 is
            const auto vsp_lane_mask = 0b11 << vsp_lane * 2;
            move_mask &= ~vsp_lane_mask; // remove those bits which represent the lane because we want them at 0
            move_mask &= vsp_lane; // this will move qword0 to vsp lane

            out.make(m_vpermq, reg_op(ymm_vsp), reg_op(ymm_vsp), imm_op(move_mask))
               .make(m_vmovq, reg_op(vsp), reg_op(vsp_xmm))
               .make(m_vpermq, reg_op(ymm_vsp), reg_op(ymm_vsp), imm_op(move_mask));
        }
        else out.make(m_vmovq, reg_op(vsp), reg_op(vsp_xmm));

        out
            // calculate target lane where our value will be stored
            // vsp % 256 / 64
            .make(m_and, reg_op(vsp), imm_op(0xFF))
            .make(m_shr, reg_op(vsp), imm_op(6))
            .make(m_mov, reg_op(lane_holder), imm_op(1))
            .make(m_shlx, reg_op(lane_holder), reg_op(lane_holder), reg_op(vsp))
            .make(m_kmovb, reg_op(k1), reg_op(lane_holder))

            // set up all ranges
            // each range represents a uint16 in the "range_boundaries" YMM register
            // [256, 512, 768, 1024, 1280, 1536, 1792, 2048]
            // range_boundaries now contains u32 lanes which hold boundaries
            .make(m_vmovdqu, reg_op(ymm_bound), reg_mem())

            // broadcast VSP to every single u32 in vsp_holder
            // compare vsp_holder < range_boundaries
            // get mask for cmp_holder
            .make(m_vbroadcastss, reg_op(ymm_vsp), reg_op(vsp)) // change to read from ymm
            .make(m_vpcmpgtd, reg_op(ymm_cmp), reg_op(ymm_bound), reg_op(ymm_vsp))
            .make(m_vpmovmskb, reg_op(mask_holder), reg_op(ymm_cmp))

            // move the mask generate by m_vpmovmskb into a reg
            // calculate target YMM
            .make(m_tzcnt, reg_op(mask_holder), reg_op(mask_holder))
            .make(m_shr, reg_op(mask_holder), imm_op(3));

        out.make(m_vbroadcastsd, reg_op(ymm_broad_value), reg_op(input_reg));

        const auto stack_order = reg_man->get_stack_order();
        for (int i = 0; i < stack_order.size(); i++)
        {
            const bool is_not_last = i != stack_order.size() - 1;
            auto skip_label = asmb::code_label::create();

            const reg reg = stack_order[i];
            if (is_not_last)
                out.make(m_cmp, reg_op(mask_holder), imm_op((i + 1) * 256))
                   .make(m_jnl, imm_label_operand(skip_label));

            out.make(m_vmovdqu32, reg_op(reg), reg_op(k1), reg_op(ymm_broad_value));

            if (is_not_last)
                out.label(skip_label);
        }

        sub_vsp(out);
    }

    inline void pop_64(codec::reg dest, encode_builder& out)
    {
        add_vsp(out);
    }
}
