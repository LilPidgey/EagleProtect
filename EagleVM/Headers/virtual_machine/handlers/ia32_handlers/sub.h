#include "virtual_machine/handlers/vm_handler_entry.h"

class ia32_sub_handler : public vm_handler_entry
{
public:
    ia32_sub_handler();

private:
    virtual handle_instructions construct_single(reg_size size) override;
};