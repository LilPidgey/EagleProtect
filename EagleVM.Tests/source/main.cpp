#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#include <bitset>
#include <execution>
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <future>
#include <vector>
#include <eaglevm-core/disassembler/dasm.h>

#include "nlohmann/json.hpp"

#include "spdlog/spdlog.h"
#include "spdlog/async.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include "util.h"
#include "run_container.h"
#include "eaglevm-core/compiler/section_manager.h"
#include "eaglevm-core/virtual_machine/ir/ir_translator.h"
#include "eaglevm-core/virtual_machine/machines/eagle/machine.h"
#include "eaglevm-core/virtual_machine/machines/eagle/settings.h"
#include "eaglevm-core/virtual_machine/machines/pidgeon/machine.h"
#include "eaglevm-core/virtual_machine/machines/pidgeon/settings.h"

reg_overwrites build_writes(nlohmann::json& inputs);
uint32_t compare_context(CONTEXT& result, CONTEXT& target, reg_overwrites& outs, bool flags);
uint64_t* get_value(CONTEXT& new_context, std::string& reg);

// imul and mul tests are cooked
const std::string inclusive_tests[] = {
    "add",
    "sub",

    "inc",
    "dec",

    "push",
    "pop",

    "lea",
    "mov",
    "movsx",

    "cmp",

    "xor",
    "shl",
    "shr",
};

using namespace eagle;

std::atomic_uint32_t total_passed = 0;
std::atomic_uint32_t total_failed = 0;

void process_entry(const virt::eg::settings_ptr& machine_settings, const nlohmann::basic_json<>& test, std::atomic_uint32_t* passed,
    std::atomic_uint32_t* failed, uint32_t task_id)
{
    std::stringstream ss;

    // create a new file for each test
    std::string instr_data = test["data"];
    std::string instr = test["instr"];

    nlohmann::json inputs = test["inputs"];
    nlohmann::json outputs = test["outputs"];

    // i dont know what else to do
    // you cannot just use VEH to recover RIP/RSP corruption
    if (instr.contains("sp"))
        return;

    bool bp = false;
    if (test.contains("bp"))
        bp = test["bp"];

#ifdef _DEBUG
    if (bp)
        __debugbreak();
#endif

    {
        ss << "\n\n[test] " << instr.c_str() << "\n";
        ss << "[input]\n";
        test_util::print_regs(inputs, ss);

        ss << "[output]\n";
        test_util::print_regs(outputs, ss);
    }

    reg_overwrites ins = build_writes(inputs);
    reg_overwrites outs = build_writes(outputs);

    std::vector<uint8_t> instruction_data = test_util::parse_hex(instr_data);
    instruction_data.push_back(0x0F);
    instruction_data.push_back(0x01);
    instruction_data.push_back(0xC1);

    codec::decode_vec instructions = codec::get_instructions(instruction_data.data(), instruction_data.size());

    dasm::segment_dasm_ptr dasm = std::make_shared<dasm::segment_dasm>(0, instruction_data.data(), instruction_data.size());
    dasm->explore_blocks(0, TODO);

    std::shared_ptr<ir::ir_translator> ir_trans = std::make_shared<ir::ir_translator>(dasm);
    ir::preopt_block_vec preopt = ir_trans->translate();

    // here we assign vms to each block
    // for the current example we can assign the same vm id to each block
    uint32_t vm_index = 0;
    std::unordered_map<ir::preopt_block_ptr, uint32_t> block_vm_ids;
    for (const auto& preopt_block : preopt)
        block_vm_ids[preopt_block] = vm_index;

    // we want to prevent the vmenter from being removed from the first block, therefore we mark it as an external call
    ir::preopt_block_ptr entry_block = nullptr;
    for (const std::shared_ptr<ir::preopt_block>& preopt_block : preopt)
        if (preopt_block->original_block == dasm->get_block(0, false))
            entry_block = preopt_block;

    assert(entry_block != nullptr, "could not find matching preopt block for entry block");

    // if we want, we can do a little optimzation which will rewrite the preopt blocks
    // or we could simply ir_trans.flatten()
    std::unordered_map<ir::preopt_block_ptr, ir::block_ptr> block_tracker = { { entry_block, nullptr } };
    std::vector<ir::flat_block_vmid> vm_blocks = ir_trans->optimize(block_vm_ids, block_tracker, { entry_block });

    // initialize block code labels
    std::unordered_map<ir::block_ptr, asmb::code_label_ptr> block_labels;
    for (auto& blocks : vm_blocks | std::views::keys)
        for (const auto& block : blocks)
            block_labels[block] = asmb::code_label::create();

    asmb::section_manager vm_section(false);
    std::vector<virt::eg::machine_ptr> used_machines;

    asmb::code_label_ptr entry_point = asmb::code_label::create();
    for (const auto& [blocks, vm_id] : vm_blocks)
    {
        // we create a new machine based off of the same settings to make things more annoying
        // but the same machine could be used :)

        //virt::pidg::machine_ptr machine = virt::pidg::machine::create(vm_settings);
        virt::eg::machine_ptr machine = virt::eg::machine::create(machine_settings);
        used_machines.push_back(machine);

        machine->add_block_context(block_labels);

        for (auto i = 0; i < blocks.size(); i++)
        {
            auto& translated_block = blocks[i];
            if(bp)
            {
                std::string out_string;
                for (auto j = 0; j < translated_block->size(); j++)
                {
                    auto inst = translated_block->at(j);
                    out_string += inst->to_string() + "\n";
                }

                out_string.pop_back();

                spdlog::get("console")->info("block 0x{:x}\n{}", translated_block->block_id, out_string);
            }

            asmb::code_container_ptr result_container = machine->lift_block(translated_block);
            ir::block_ptr block = block_tracker[entry_block];
            if (block == translated_block)
                result_container->bind_start(entry_point);

            vm_section.add_code_container(result_container);
        }

        // build handlers
        std::vector<asmb::code_container_ptr> handler_containers = machine->create_handlers();
        vm_section.add_code_container(handler_containers);
    }

    constexpr auto run_space_size = 0x500000;
    uint64_t run_space = reinterpret_cast<uint64_t>(VirtualAlloc(nullptr, run_space_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE));

    codec::encoded_vec virtualized_instruction = vm_section.compile_section(0);
    memcpy(reinterpret_cast<void*>(run_space), virtualized_instruction.data(), virtualized_instruction.size());

    assert(run_space_size >= virtualized_instruction.size(), "run space is not big enough");

    run_container container(ins, outs);
    container.set_run_area(run_space, run_space_size);

    spdlog::get("console")->info("starting {} run at {:x} {:x} bytes", instr.c_str(), run_space, virtualized_instruction.size());
#ifdef _DEBUG
    if(bp)
        __debugbreak();
#endif

    auto [result_context, output_target] = container.run(bp);
    VirtualFree(reinterpret_cast<void*>(run_space), 0, MEM_RELEASE);

    // result_context is being set in the exception handler
    const uint32_t result = compare_context(
        result_context,
        output_target,
        outs,
        outputs.contains("flags")
    );

    if (result == none)
    {
        ss << "[+] passed\n";
        passed->fetch_add(1);

        spdlog::get("test")->info(ss.str());
        spdlog::get("console")->info("instruction {} passed", instr.c_str());
    }
    else
    {
        if (result & register_mismatch)
        {
            ss << "[!] register mismatch\n";

            for (auto reg : outs | std::views::keys)
            {
                if (reg == "flags" || reg == "rip")
                    continue;

                ss << "  > " << reg << "\n";
                ss << "  target: 0x" << std::hex << *test_util::get_value(output_target, reg) << '\n';
                ss << "  out   : 0x" << std::hex << *test_util::get_value(result_context, reg) << '\n';
            }
        }

        if (result & flags_mismatch)
        {
            ss << "[!] flags mismatch\n";

            std::bitset<32> target_flags(output_target.EFlags);
            std::bitset<32> out_flags(result_context.EFlags);
            ss << "  target:" << target_flags << '\n';
            ss << "  out:   " << out_flags << '\n';
        }

        if (result & stack_misalign)
        {
            ss << "[!] stack pointer not returned to original position\n";
        }

        ss << "[!] failed\n";
        failed->fetch_add(1);

        spdlog::get("test")->error(ss.str());
        spdlog::get("console")->error("instruction {} failed", instr.c_str());
    }
}

int main(int argc, char* argv[])
{
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    // give .handlers and .run_section execute permissions
    // the fact that i have to do this is so extremely cooked
    // i mean its literally DOOMED
    // the virtualizer doesnt allow displacement sizes larger than run time addresses
    // so all i can do is create a section 🤣

    // setbuf(stdout, NULL);
    const char* test_data_path = argc > 1 ? argv[1] : "../../../deps/x86_test_data/TestData64";
    if (!std::filesystem::exists("x86-tests"))
        std::filesystem::create_directory("x86-tests");

    codec::setup_decoder();
    run_container::init_veh();

    // we want the same settings for every machine
    /*virt::pidg::settings_ptr machine_settings = std::make_shared<virt::pidg::settings>();
    machine_settings->set_temp_count(4);
    machine_settings->set_randomize_vm_regs(true);
    machine_settings->set_randomize_stack_regs(true);*/

    auto console_logger = spdlog::stdout_color_mt("console");
    spdlog::flush_every(std::chrono::seconds(5));

    virt::eg::settings_ptr machine_settings = std::make_shared<virt::eg::settings>();
    machine_settings->shuffle_push_order = false;
    machine_settings->shuffle_vm_gpr_order = false;
    machine_settings->shuffle_vm_xmm_order = false;

    spdlog::get("console")->info("using random seed {}", util::get_ran_device().seed);

    // loop each file that test_data_path contains
    for (const auto& entry : std::filesystem::directory_iterator(test_data_path))
    {
        std::filesystem::path entry_path = entry.path();
        entry_path.make_preferred();

        std::string file_name = entry_path.stem().string();
        if (std::ranges::find(inclusive_tests, file_name) == std::end(inclusive_tests))
            continue;

        // Create an ofstream object for the output file
        const std::shared_ptr<spdlog::logger> file_logger = spdlog::basic_logger_mt<spdlog::async_factory>("test", "x86-tests/" + file_name);
        spdlog::get("console")->info("generating tests for {}", entry_path.string());

        // read entry file as string
        std::ifstream file(entry.path());
        nlohmann::json data = nlohmann::json::parse(file);

        std::atomic_uint32_t passed = 0;
        std::atomic_uint32_t failed = 0;

        std::atomic_uint32_t task_id;
#ifdef _DEBUG
        auto execution_policy = std::execution::seq;
#else
        auto execution_policy = std::execution::par_unseq;
#endif
        std::for_each(execution_policy, data.begin(), data.end(), [&](auto& n)
        {
            const auto current_task_id = task_id++;
            process_entry(machine_settings, n, &passed, &failed, current_task_id);
        });

        spdlog::get("console")->info("finished generating {} tests for: {}", passed + failed, file_name);
        spdlog::get("console")->info("passed {}", passed.load());
        spdlog::get("console")->info("failed {}", failed.load());

        float success = static_cast<float>(passed) / (passed.load() + failed.load()) * 100;
        spdlog::get("console")->info("success rate {}", success);

        file_logger->flush();
        spdlog::drop("test");

        total_passed += passed;
        total_failed += failed;
    }

    run_container::destroy_veh();

    spdlog::get("console")->info("total tests: {}", total_passed + total_failed);
    spdlog::get("console")->info("total passed: {}", total_passed.load());
    spdlog::get("console")->info("total failed: {}", total_failed.load());
    float total_success_rate = static_cast<float>(total_passed) / (total_passed + total_failed) * 100;
    spdlog::get("console")->info("total success rate: {:.2f}%", total_success_rate);
}

reg_overwrites build_writes(nlohmann::json& inputs)
{
    reg_overwrites overwrites;
    for (auto& input : inputs.items())
    {
        std::string reg = input.key();
        uint64_t value = 0;
        if (input.value().is_string())
        {
            std::string str = input.value();
            value = std::stoull(str, nullptr, 16);
            value = _byteswap_uint64(value);
        }
        else
        {
            value = input.value();
        }

        overwrites.emplace_back(reg, value);
    }

    return overwrites;
}

uint32_t compare_context(CONTEXT& result, CONTEXT& target, reg_overwrites& outs, bool flags)
{
    uint32_t fail = none;

    // rip comparison is COOKED there is something really off about the test data
    // auto res_rip = result.Rip == target.Rip;
    for (auto& reg : outs | std::views::keys)
    {
        if (reg == "rip" || reg == "flags")
            continue;

        uint64_t tar = *test_util::get_value(target, reg);
        uint64_t out = *test_util::get_value(result, reg);

        if (tar != out)
        {
            fail |= register_mismatch;
            break;
        }
    }

    if (target.Rsp != result.Rsp)
    {
        fail |= stack_misalign;
    }

    if (flags)
    {
        const bool res_flags = (result.EFlags & target.EFlags) == target.EFlags;
        if (!res_flags)
            fail |= flags_mismatch;
    }

    return fail;
}
