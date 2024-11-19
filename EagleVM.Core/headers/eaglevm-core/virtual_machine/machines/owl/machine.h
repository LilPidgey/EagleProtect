#pragma once
#include <vector>
#include "eaglevm-core/virtual_machine/machines/base_machine.h"
#include "eaglevm-core/virtual_machine/machines/register_context.h"
#include "eaglevm-core/virtual_machine/machines/owl/register_manager.h"
#include "eaglevm-core/virtual_machine/machines/owl/settings.h"
#include "eaglevm-core/virtual_machine/machines/util/hash.h"

#include "eaglevm-core/codec/zydis_encoder.h"

namespace eagle::virt::owl
{
    using machine_ptr = std::shared_ptr<class machine>;
    class machine final : public base_machine
    {
    public:
        explicit machine(const settings_ptr& settings_info);
        static machine_ptr create(const settings_ptr& settings_info);

        asmb::code_container_ptr lift_block(const ir::block_ptr& block) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_context_load_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_context_store_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_branch_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_handler_call_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_mem_read_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_mem_write_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_pop_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_push_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_context_rflags_load_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_context_rflags_store_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_sx_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_vm_enter_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_vm_exit_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_x86_exec_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_flags_load_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_jmp_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_and_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_or_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_xor_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_shl_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_shr_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_add_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_sub_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_cmp_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_resize_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_cnt_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_smul_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_umul_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_abs_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_log2_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_dup_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_call_ptr& cmd) override;
        void handle_cmd(const asmb::code_container_ptr& block, const ir::cmd_ret_ptr& cmd) override;

        std::vector<asmb::code_container_ptr> create_handlers() override;

    private:
        settings_ptr settings;

        register_manager_ptr regs;
        register_context_ptr reg_64_container;
        register_context_ptr reg_256_container;

        using handler_info_pair = std::pair<asmb::code_label_ptr, asmb::code_container_ptr>;
        std::unordered_map<size_t, std::vector<handler_info_pair>> handler_map;
        std::vector<handler_info_pair> misc_handlers;

        [[nodiscard]] codec::reg reg_vm_to_register(ir::reg_vm store) const;
        void handle_generic_logic_cmd(codec::mnemonic command, ir::ir_size ir_size, bool preserved, codec::encoder::encode_builder& out,
            const std::function<codec::reg()>& alloc_reg);

        void push_lane_64(codec::reg input_reg, uint16_t input_lane, codec::encoder::encode_builder& out);
        void push_64(codec::reg input_reg, codec::encoder::encode_builder& out);

        std::pair<codec::reg, codec::reg> peek_stack(uint8_t index = 0);
        void pop_lane_64(codec::reg input_reg, uint16_t input_lane, codec::encoder::encode_builder& out);
        void pop_64(codec::reg dest, codec::encoder::encode_builder& out);

        void gen_vsp_modification(codec::encoder::encode_builder& out, bool sub);
        void sub_vsp(codec::encoder::encode_builder& out);
        void add_vsp(codec::encoder::encode_builder& out);

        // has to set lane register to 0
        void move_qlane_to_bottom(codec::reg ymm, codec::reg lane, codec::encoder::encode_builder& out);

        // reads value into lane register
        void read_qlane_to_gpr(codec::reg ymm, codec::reg lane, codec::encoder::encode_builder& out);

        enum handler_call_flags
        {
            default_create = 0,
            force_inline = 1,
            force_unique = 2,
        };

        using handler_generator = std::function<void(const asmb::code_container_ptr&, std::function<codec::reg()>)>;

        template <typename... Params>
        void create_handler(handler_call_flags flags, const asmb::code_container_ptr& block, const ir::base_command_ptr& command,
            const handler_generator handler_create, const Params&... params)
        {
            const size_t handler_hash = compute_handler_hash(command->get_command_type(), params...);
            if (command->is_inlined())
                flags = force_inline;

            create_handler(flags, block, handler_create, handler_hash);
        }

        void create_handler(handler_call_flags flags, const asmb::code_container_ptr& block, const handler_generator& create, size_t handler_hash);
    };
}
