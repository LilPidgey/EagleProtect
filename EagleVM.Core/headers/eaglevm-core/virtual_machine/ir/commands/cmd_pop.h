#pragma once
#include <utility>

#include "eaglevm-core/virtual_machine/ir/commands/base_command.h"

namespace eagle::ir
{
    class cmd_pop : public base_command
    {
    public:
        explicit cmd_pop(discrete_store_ptr reg_dest, ir_size size);

        discrete_store_ptr get_destination_reg();
        ir_size get_size() const;

        bool is_similar(const std::shared_ptr<base_command>& other) override;

        std::vector<discrete_store_ptr> get_use_stores() override;

    private:
        discrete_store_ptr dest_reg;
        ir_size size;
    };
}
