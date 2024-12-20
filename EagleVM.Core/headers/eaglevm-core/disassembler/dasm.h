#pragma once
#include <queue>
#include <tuple>

#include "eaglevm-core/disassembler/models/branch_info.h"
#include "eaglevm-core/disassembler/basic_block.h"
#include "eaglevm-core/codec/zydis_helper.h"

namespace eagle::dasm
{
    class segment_dasm_kernel
    {
    public:
        virtual ~segment_dasm_kernel() = default;

    protected:
        /// @brief decodes an instruction at the specified rva.
        /// @return pair [decoded instruction info, size of instruction]
        /// @ensures out = decoded instruction information and size of the instruction
        virtual std::pair<codec::dec::inst_info, uint8_t> decode_instruction(uint64_t rva) = 0;

        /// @brief retrieves branches for the instruction at the specified rva.
        /// @return branching information about the current instruction
        /// @ensures out = branching information for the given rva
        virtual std::vector<branch_info_t> get_branches(uint64_t rva) = 0;
    };

    class base_segment_dasm : public segment_dasm_kernel
    {
    public:
        /// @brief given an entry address, the function will return a set of basic blocks
        /// which are explored by the control flow of the given instructions
        /// @param entry_rva rva at which the control flow begins
        /// @param discovery_depth
        /// @return basic blocks which represent the generated control flow
        /// @ensures out = set of basic blocks representing the control flow
        virtual std::vector<basic_block_ptr> explore_blocks(uint64_t entry_rva,
            std::optional<std::reference_wrapper<std::unordered_map<basic_block_ptr, uint32_t>>> discovery_depth) = 0;

        /// @brief gets all the instructions in a certain section and disregards the flow of the instructions
        /// @param rva_begin the rva at which the starting instruction is at
        /// @param rva_end the inclusive rva at which the last instruction ends
        /// @return the list of instructions which are contained within this range
        /// @ensures out = all sequential instructions in range [rva_begin, rva_end]
        virtual basic_block_ptr dump_section(uint64_t rva_begin, uint64_t rva_end) = 0;

        /// @brief disassembled instructions until a branching instruction is reached at the current block
        /// @param rva the rva at which the target block begins
        /// @param inclusive if inclusive, then the bounds of the block will be checked for the rva
        /// otherwise, only the starting rva of the block will be used to match the "rva" parameter
        /// @return the basic block the instructions create
        /// @ensures if inclusive, out.rva >= rva && rva < out.end; otherwise out.rva = rva
        virtual basic_block_ptr get_block(uint32_t rva, bool inclusive) = 0;
    };

    class segment_dasm : public base_segment_dasm
    {
    public:
        /// @brief
        /// @param rva_base base rva of the instructions which will be decoded
        /// @param buffer read only buffer pointer to instructions
        /// @param size size of buffer. use to determine end inclusive rva as well
        /// @ensures constructs a segment_dasm instance with a given base rva and instruction buffer
        segment_dasm(uint64_t rva_base, uint8_t* buffer, size_t size);

        /// @brief given an entry address, the function will return a set of basic blocks
        /// which are explored by the control flow of the given instructions
        /// @param entry_rva rva at which the control flow begins
        /// @param discovery_depth optional discovery information for basic blocks
        /// @return basic blocks which represent the generated control flow
        /// @ensures out = set of basic blocks representing the control flow
        std::vector<basic_block_ptr> explore_blocks(uint64_t entry_rva,
            std::optional<std::reference_wrapper<std::unordered_map<basic_block_ptr, uint32_t>>> discovery_depth = std::nullopt) override;

        /// @brief gets all the instructions in a certain section and disregards the flow of the instructions
        /// @param rva_begin the rva at which the starting instruction is at
        /// @param rva_end the inclusive rva at which the last instruction ends
        /// @return the list of instructions which are contained within this range
        /// @ensures out = all sequential instructions in rva_begin -> rva_end
        basic_block_ptr dump_section(uint64_t rva_begin, uint64_t rva_end) override;

        /// @brief disassembled instructions until a branching instruction is reached at the current block
        /// @param rva the rva at which the target block begins
        /// @param inclusive if inclusive, then the bounds of the block will be checked for the rva
        /// otherwise, only the starting rva of the block will be used to match the "rva" parameter
        /// @return the basic block the instructions create
        /// @ensures if inclusive, out.rva >= rva < out.end. else out.rva = rva
        basic_block_ptr get_block(uint32_t rva, bool inclusive) override;

        /// @return basic blocks accumulated in the instance of the generation
        /// @ensures out = block captures by exploration
        std::vector<basic_block_ptr>& get_blocks();

        /// @return string state of the disassembly instance
        /// @ensures out = [segment_dasm] rva_base: instruction_buffer: instruction_size:
        [[nodiscard]] std::string to_string() const;

        /// @return true if both instances are equal, ignoring state of created blocks
        /// @ensures out = equivalency between the managed section is disassembler
        bool operator==(const segment_dasm&) const;

    private:
        uint64_t rva_base;
        uint8_t* instruction_buffer;
        size_t instruction_size;

        std::vector<basic_block_ptr> blocks;

        /// @brief decodes an instruction at the specified rva.
        /// @return pair [decoded instruction info, size of instruction]
        // @ensures out = decoded instruction information and size of the instruction
        std::pair<codec::dec::inst_info, uint8_t> decode_instruction(uint64_t rva) override;

        /// @brief retrieves branches for the instruction at the specified rva.
        /// @return branching information about the current instruction
        /// @ensures out = branching information for the given rva
        std::vector<branch_info_t> get_branches(uint64_t rva) override;
    };

    using segment_dasm_ptr = std::shared_ptr<segment_dasm>;
}
