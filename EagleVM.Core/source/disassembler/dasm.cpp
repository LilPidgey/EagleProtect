#include "eaglevm-core/disassembler/dasm.h"

#include <unordered_set>

namespace eagle::dasm
{
    segment_dasm::segment_dasm(const uint64_t rva_base, uint8_t* buffer, const size_t size):
        rva_base(rva_base), instruction_buffer(buffer), instruction_size(size)
    {
    }

    std::vector<basic_block_ptr> segment_dasm::explore_blocks(const uint64_t entry_rva,
        std::optional<std::reference_wrapper<std::unordered_map<basic_block_ptr, uint32_t>>> discovery_depth)
    {
        std::vector<basic_block_ptr> collected_blocks;

        std::unordered_set<uint64_t> discovered;
        std::queue<uint64_t> explore_queue;
        explore_queue.push(entry_rva);
        discovered.insert(entry_rva);

        uint32_t depth = 0;
        while (!explore_queue.empty())
        {
            const size_t layer_size = explore_queue.size();
            for (int i = 0; i < layer_size; i++)
            {
                const uint32_t layer_rva = explore_queue.front();
                explore_queue.pop();

                // check if we are in the middle of an already existing block
                // if so, we split up the block and we just continue
                bool should_continue = false;
                for (const auto& existing : collected_blocks)
                {
                    if (layer_rva >= existing->start_rva && layer_rva < existing->end_rva_inc)
                    {
                        auto prev = std::make_shared<basic_block>();
                        prev->start_rva = existing->start_rva;
                        prev->end_rva_inc = prev->start_rva;

                        existing->start_rva = layer_rva;

                        while (prev->end_rva_inc < layer_rva)
                        {
                            auto block_inst = existing->decoded_insts.front();
                            prev->decoded_insts.push_back(block_inst);
                            existing->decoded_insts.erase(existing->decoded_insts.begin());

                            prev->end_rva_inc += block_inst.instruction.length;
                        }

                        if (discovery_depth)
                        {
                            auto& map = discovery_depth->get();
                            map[prev] = depth++;
                        }

                        // this means there is some tricky control flow happening
                        // for instance, there may be an opaque branch to some garbage code
                        // another reason could be is we explored the wrong branch first of some obfuscated code and found garbage
                        // this will not happen with normally compiled code
                        VM_ASSERT(prev->end_rva_inc == layer_rva, "resulting jump is between an already explored instruction");
                        collected_blocks.push_back(prev);

                        should_continue = true;
                        break;
                    }
                }

                if (should_continue)
                    continue;

                basic_block_ptr block = std::make_shared<basic_block>();
                block->start_rva = layer_rva;

                if (discovery_depth)
                {
                    auto& map = discovery_depth->get();
                    map[block] = depth++;
                }

                uint32_t current_rva = layer_rva;
                while (true)
                {
                    // we must do a check to see if our rva is at some already existing block,
                    // if so, we are going to end this block
                    bool force_create = false;
                    for (const auto& created_block : collected_blocks)
                    {
                        if (current_rva >= created_block->start_rva && current_rva < created_block->end_rva_inc)
                        {
                            // we are inside
                            VM_ASSERT(current_rva == created_block->start_rva, "instruction overlap caused by seeking block");
                            force_create = true;
                            break;
                        }
                    }

                    if (force_create || current_rva >= rva_base + instruction_size)
                        break;

                    auto [decode_info, inst_size] = decode_instruction(current_rva);
                    block->decoded_insts.push_back(decode_info);

                    if (decode_info.instruction.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE &&
                        decode_info.instruction.mnemonic != ZYDIS_MNEMONIC_CALL)
                    {
                        // branching instruction encountered
                        auto branches = get_branches(current_rva);
                        for (auto& [is_resolved, is_ret, target_rva] : branches)
                            if (is_resolved)
                            {
                                if (!discovered.contains(target_rva))
                                {
                                    explore_queue.push(target_rva);
                                    discovered.insert(target_rva);
                                }
                            }

                        force_create = true;
                    }

                    current_rva += inst_size;
                    if (force_create)
                        break;
                }

                block->end_rva_inc = current_rva;
                collected_blocks.push_back(block);
            }
        }

        // i will just say, this is an insane way to do it,
        // but keeping up with these during analysis is a bit annoying
        // and im lazy, so this will not be getting changed until i care
        // todo: above rant
        for (const auto& block : collected_blocks)
        {
            const auto end_inst = block->end_rva_inc - block->decoded_insts.back().instruction.length;
            block->branches = get_branches(end_inst);
        }

        blocks = collected_blocks;
        return collected_blocks;
    }

    basic_block_ptr segment_dasm::dump_section(uint64_t rva_begin, const uint64_t rva_end)
    {
        basic_block_ptr block = std::make_shared<basic_block>();
        while (rva_begin < rva_end)
        {
            codec::dec::inst_info inst = codec::get_instruction(
                instruction_buffer,
                instruction_size,
                rva_begin - rva_base
            );

            block->decoded_insts.push_back(inst);
            rva_begin += inst.instruction.length;
        }

        return block;
    }

    basic_block_ptr segment_dasm::get_block(const uint32_t rva, bool inclusive)
    {
        for (auto block : blocks)
        {
            if (inclusive)
            {
                if (rva >= block->start_rva && rva < block->end_rva_inc)
                    return block;
            }
            else
            {
                if (rva == block->start_rva)
                    return block;
            }
        }

        return nullptr;
    }

    std::vector<basic_block_ptr>& segment_dasm::get_blocks()
    {
        return blocks;
    }

    std::string segment_dasm::to_string() const
    {
        std::stringstream str;
        str << "[segment_dasm]";
        str << "\n    rva_base: " << std::hex << rva_base;
        str << "\n    instruction_buffer: " << std::hex << instruction_buffer;
        str << "\n    instruction_size: " << std::hex << instruction_size;

        return str.str();
    }

    bool segment_dasm::operator==(const segment_dasm& other) const
    {
        return rva_base == other.rva_base && instruction_buffer == other.instruction_buffer && rva_base == other.rva_base;
    }

    std::pair<codec::dec::inst_info, uint8_t> segment_dasm::decode_instruction(const uint64_t rva)
    {
        codec::dec::inst_info inst = codec::get_instruction(
            instruction_buffer,
            instruction_size,
            rva - rva_base
        );

        return { inst, inst.instruction.length };
    }

    std::vector<branch_info_t> segment_dasm::get_branches(uint64_t rva)
    {
        auto [instruction, operands] = codec::get_instruction(
            instruction_buffer,
            instruction_size,
            rva - rva_base
        );

        std::vector<branch_info_t> branches;
        if (instruction.mnemonic == codec::m_ret)
        {
            branches.push_back(branch_info_t{
                false,
                true,
                0
            });

            return branches;
        }

        if (is_jmp_or_jcc(static_cast<codec::mnemonic>(instruction.mnemonic)))
        {
            auto [target, op_idx] = codec::calc_relative_rva(instruction, operands, rva);
            branches.push_back(branch_info_t{
                op_idx != -1,
                false,
                target
            });

            if (instruction.mnemonic == codec::m_jmp)
                return branches;
        }

        branches.push_back(branch_info_t{
            true,
            false,
            rva + instruction.length
        });

        return branches;
    }
}
