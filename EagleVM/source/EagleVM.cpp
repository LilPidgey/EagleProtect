#include <algorithm>
#include <filesystem>
#include <ranges>

#include "eaglevm-core/util/util.h"

#include "eaglevm-core/compiler/section_manager.h"
#include "eaglevm-core/pe/packer/pe_packer.h"
#include "eaglevm-core/pe/pe_generator.h"

#include <linuxpe>

#include "eaglevm-core/disassembler/analysis/liveness.h"
#include "eaglevm-core/disassembler/dasm.h"
#include "eaglevm-core/pe/models/stub.h"
#include "eaglevm-core/virtual_machine/ir/ir_translator.h"
#include "eaglevm-core/virtual_machine/ir/obfuscator/obfuscator.h"

#include "eaglevm-core/virtual_machine/machines/pidgeon/inst_handlers.h"
#include "eaglevm-core/virtual_machine/machines/pidgeon/machine.h"

#include "eaglevm-core/virtual_machine/machines/eagle/machine.h"

using namespace eagle;

void print_liveness(dasm::analysis::liveness& seg_live, std::vector<dasm::basic_block_ptr>& blocks)
{
    for (auto& block : blocks)
    {
        printf("\nblock 0x%llx-0x%llx\n", block->start_rva, block->end_rva_inc);

        auto bitfield_to_bitstring = [](const uint64_t value, const auto sig_bits) -> std::string
        {
            std::string result;
            for (int k = sig_bits - 1; k >= 0; --k)
                result += value & 1 << k ? '1' : '0';

            return result;
        };

        printf("in: \n");
        dasm::analysis::liveness_info& item = seg_live.live[block].first;
        for (int k = ZYDIS_REGISTER_RAX; k <= ZYDIS_REGISTER_R15; k++)
            if (auto res = item.get_gpr64(static_cast<codec::reg>(k)))
                printf("\t%s:%s\n", reg_to_string(static_cast<codec::reg>(k)), bitfield_to_bitstring(res, 8).c_str());

        printf("out: \n");
        item = seg_live.live[block].second;
        for (int k = ZYDIS_REGISTER_RAX; k <= ZYDIS_REGISTER_R15; k++)
            if (auto res = item.get_gpr64(static_cast<codec::reg>(k)))
                printf("\t%s:%s\n", reg_to_string(static_cast<codec::reg>(k)), bitfield_to_bitstring(res, 8).c_str());

        auto block_liveness = seg_live.analyze_block(block);

        printf("insts: \n");
        for (size_t idx = 0; auto& inst : block->decoded_insts)
        {
            std::string inst_string = codec::instruction_to_string(inst);
            printf("\t%llu. %s\n", idx, inst_string.c_str());

            printf("\tin: \n");
            for (int k = ZYDIS_REGISTER_RAX; k <= ZYDIS_REGISTER_R15; k++)
                if (auto res = block_liveness[idx].first.get_gpr64(static_cast<codec::reg>(k)))
                    printf("\t\t%s:%s\n", reg_to_string(static_cast<codec::reg>(k)), bitfield_to_bitstring(res, 8).c_str());

            if (auto res = block_liveness[idx].first.get_flags())
                printf("\t\trflags:%s\n", bitfield_to_bitstring(res, 32).c_str());

            printf("\tout: \n");
            for (int k = ZYDIS_REGISTER_RAX; k <= ZYDIS_REGISTER_R15; k++)
                if (auto res = block_liveness[idx].second.get_gpr64(static_cast<codec::reg>(k)))
                    printf("\t\t%s:%s\n", reg_to_string(static_cast<codec::reg>(k)), bitfield_to_bitstring(res, 8).c_str());

            if (auto res = block_liveness[idx].second.get_flags())
                printf("\t\trflags:%s\n", bitfield_to_bitstring(res, 32).c_str());

            idx++;
        }
    }
}

void print_ir_graphviz(
    const std::vector<std::pair<uint32_t, std::vector<ir::block_ptr>>>& grouped_blocks,
    const ir::block_ptr& entry,
    const std::vector<ir::block_ptr>& alternative_handlers)
{
    std::cout << "digraph ControlFlow {\n"
        << "  graph [splines=ortho, rankdir=LR]\n" // Set graph direction to top-to-bottom
        << "  node [shape=box, fontname=\"Courier\"];\n";

    std::vector<std::string> edges;
    std::map<uint32_t, std::vector<std::string>> depth_map;
    for (const auto& [group_depth, blocks] : grouped_blocks)
    {
        for (const ir::block_ptr& block : blocks)
        {
            const std::string node_id = std::format("0x{:x}", block->block_id);
            std::string graph_title = block == entry ? node_id + " (entry)" : node_id;

            // Add node to the depth map
            depth_map[group_depth].push_back(node_id);

            std::ostringstream insts_nodes;
            for (const auto& inst : *block)
                insts_nodes << std::format("<TR><TD ALIGN=\"LEFT\">{}</TD></TR>", inst->to_string());

            std::cout << std::format(
                "  \"{}\" [label=<<TABLE BORDER=\"0\">"
                "<TR><TD ALIGN=\"CENTER\"><B>block {}</B></TD></TR>"
                "{}"
                "</TABLE>>];\n",
                node_id, graph_title, insts_nodes.str());

            std::vector<ir::ir_exit_result> branches;
            if (const auto ptr_virt = block->as_virt())
            {
                if (const auto exit = ptr_virt->exit_as_branch())
                    branches = exit->get_branches();
                else if (const auto vmexit = ptr_virt->exit_as_vmexit())
                    branches = vmexit->get_branches();

                for (const auto& call : ptr_virt->get_calls())
                    edges.push_back(std::format("  \"{}\" -> \"0x{:x}\";\n", node_id, call->block_id));
            }
            else if (auto ptr_x86 = block->as_x86())
            {
                if (const auto exit = ptr_x86->exit_as_branch())
                    branches = exit->get_branches();
            }

            for (const auto& branch : branches)
            {
                std::string target_id;
                if (std::holds_alternative<ir::block_ptr>(branch))
                    target_id = std::format("0x{:x}", std::get<ir::block_ptr>(branch)->block_id);
                else
                    target_id = std::format("0x{:x}", std::get<uint64_t>(branch));

                edges.push_back(std::format("  \"{}\" -> \"{}\";\n", node_id, target_id));
            }
        }
    }

    // Process alternative handlers
    std::vector<std::string> alternative_handler_nodes;
    for (const ir::block_ptr& handler : alternative_handlers)
    {
        const std::string node_id = std::format("0x{:x}", handler->block_id);

        std::ostringstream insts_nodes;
        for (const auto& inst : *handler)
            insts_nodes << std::format("<TR><TD ALIGN=\"LEFT\">{}</TD></TR>", inst->to_string());

        std::cout << std::format(
            "  \"{}\" [label=<<TABLE BORDER=\"0\">"
            "<TR><TD ALIGN=\"CENTER\"><B>alt block {}</B></TD></TR>"
            "{}"
            "</TABLE>>];\n",
            node_id, node_id, insts_nodes.str());

        alternative_handler_nodes.push_back(node_id);
    }

    // Print edges
    for (const auto& e : edges)
        std::cout << e;

    for (const auto& [depth, nodes] : depth_map)
    {
        std::cout << std::format("  subgraph cluster_{} {{\n", depth);
        std::cout << "    rankdir=TB;\n"; // Force top-to-bottom within the cluster
        std::cout << "    style=invis;\n"; // Make the border invisible
        for (const auto& n : nodes)
            std::cout << "    \"" << n << "\";\n";
        std::cout << "  }\n";
    }

    std::cout << "}\n" << std::flush;
}


void print_ir(const std::vector<ir::block_ptr>& blocks, const ir::block_ptr& entry)
{
    for (const ir::block_ptr& translated_block : blocks)
    {
        std::printf("block 0x%x %s\n", translated_block->block_id, translated_block == entry ? "(entry)" : "");
        for (const auto& inst : *translated_block)
            std::printf("\t%s\n", inst->to_string().c_str());
    }
}

int main(int argc, char* argv[])
{
    auto executable = argc > 1 ? argv[1] : "EagleVMSandbox.exe";
    auto parsing_type = argc > 2 ? argv[2] : nullptr;

    std::ifstream file(executable, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::printf("[!] failed to open file: %s\n", executable);
        return EXIT_FAILURE;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    char* buffer = new char[size + 1];
    if (!file.read(buffer, size))
    {
        std::printf("[!] failed to read file: %s\n", executable);
        return EXIT_FAILURE;
    }

    win::image_x64_t* parser = reinterpret_cast<win::image_x64_t*>(buffer);
    std::printf("[+] loaded %s -> %lld bytes\n", executable, size);

    std::printf("[>] image sections\n");
    std::printf("%3s %-10s %-10s %-10s\n", "", "name", "va", "size");
    for (auto section : parser->get_nt_headers()->sections())
    {
        std::printf("%10s %-10u %-10u\n", section.name.to_string().data(), section.virtual_address, section.size_raw_data);
    }

    std::printf("\n");

    auto nt_header = parser->get_nt_headers();
    std::printf("[>] image base -> 0x%llx bytes\n", nt_header->optional_header.image_base);
    std::printf("[>] section alignment -> %u bytes\n", nt_header->optional_header.section_alignment);
    std::printf("[>] file alignment -> %u bytes\n", nt_header->optional_header.file_alignment);
    std::printf("[>] stack reserve -> %I64d bytes\n", nt_header->optional_header.size_stack_reserve);
    std::printf("[>] stack commit -> %I64d bytes\n", nt_header->optional_header.size_stack_commit);
    std::printf("[>] heap reserve -> %I64d bytes\n", nt_header->optional_header.size_heap_reserve);
    std::printf("[>] heap commit -> %I64d bytes\n", nt_header->optional_header.size_heap_commit);

    std::vector<std::pair<pe::stub_import, uint32_t>> vm_iat_calls;
    if (parsing_type)
    {
        std::unordered_set<std::string> target_imports;

        std::stringstream function_list = std::stringstream(parsing_type);
        while (function_list.good())
        {
            std::string substr;
            getline(function_list, substr, ',');

            target_imports.insert(substr);
        }

        std::printf("\n[>] image exports\n");
        std::printf("%3s %-20s %-s\n", "", "address", "export");

        std::vector<std::pair<uint32_t, uint32_t>> marked_function;

        const win::data_directory_t export_data_dir = parser->get_nt_headers()->optional_header.data_directories.export_directory;
        win::export_directory_t* export_dir = parser->rva_to_ptr<win::export_directory_t>(export_data_dir.rva);
        for (auto i = 0; i < export_dir->num_names; i++)
        {
            uint32_t* address_of_names = parser->rva_to_ptr<uint32_t>(export_dir->rva_names);
            std::string import_name = std::string(parser->rva_to_ptr<char>(address_of_names[i]));

            uint16_t* address_of_name_ordinals = parser->rva_to_ptr<uint16_t>(export_dir->rva_name_ordinals);
            uint16_t name_ordinals = address_of_name_ordinals[i];

            uint32_t* address_of_functions = parser->rva_to_ptr<uint32_t>(export_dir->rva_functions);
            uint32_t function_address = address_of_functions[name_ordinals];

            std::printf("%3i %-20hhu %-s\n", i, function_address, import_name.c_str());

            if (target_imports.contains(import_name))
            {
                marked_function.emplace_back(function_address, 0);
                target_imports.erase(import_name);
            }
        }

        const auto exception_data_dir = parser->get_nt_headers()->optional_header.data_directories.exception_directory;
        const auto exception_data_dir_count = exception_data_dir.size / sizeof(win::runtime_function_t);

        win::runtime_function_t* exception_dir = parser->rva_to_ptr<win::runtime_function_t>(exception_data_dir.rva);
        for (int i = 0; i < exception_data_dir_count; i++)
        {
            auto runtime_func = &exception_dir[i];
            auto res = std::ranges::find_if(marked_function, [&](auto& a) { return a.first == runtime_func->rva_begin; });

            if (res != marked_function.end())
            {
                auto& [start, end] = *res;
                end = runtime_func->rva_end;
            }
        }

        for (auto& [start, end] : marked_function)
        {
            vm_iat_calls.emplace_back(pe::stub_import::vm_begin, parser->rva_to_fo(start));
            vm_iat_calls.emplace_back(pe::stub_import::vm_end, parser->rva_to_fo(end));
        }
    }
    else
    {
        std::printf("\n[>] image imports\n");
        std::printf("%3s %-20s %-s\n", "", "source", "import");

        const win::data_directory_t import_data_dir = parser->get_nt_headers()->optional_header.data_directories.import_directory;
        win::import_directory_t* import_sec = parser->rva_to_ptr<win::import_directory_t>(import_data_dir.rva);

        uint64_t rva_begin = 0, rva_end = 0;
        while (import_sec->rva_name)
        {
            const char* module_name = parser->rva_to_ptr<char>(import_sec->rva_name);
            win::image_thunk_data_x64_t* thunk = parser->rva_to_ptr<win::image_thunk_data_x64_t>(import_sec->rva_original_first_thunk);

            int i = 0;
            while (thunk->address)
            {
                if (!(thunk->ordinal & IMAGE_ORDINAL_FLAG))
                {
                    win::image_named_import_t* import = parser->rva_to_ptr<win::image_named_import_t>(thunk->address);
                    std::printf("%3i %-20s %-s\n", i, module_name, import->name);

                    if (strstr(import->name, "fnEagleVMBegin"))
                        rva_begin = import_sec->rva_first_thunk + i * 8;
                    else if (strstr(import->name, "fnEagleVMEnd"))
                        rva_end = import_sec->rva_first_thunk + i * 8;
                }

                i++;
                thunk++;
            }

            import_sec++;
        }

        std::printf("\n[>] searching for uses of vm macros...\n");
        for (auto section : parser->get_nt_headers()->sections())
        {
            for (auto i = section.ptr_raw_data; i < section.ptr_raw_data + section.size_raw_data; i++)
            {
                if (*parser->raw_to_ptr(i) == 0xFF && *parser->raw_to_ptr(i + 1) == 0x15)
                {
                    const auto data_segment = *parser->raw_to_ptr<uint32_t>(i + 2);
                    const auto data_rva = parser->fo_to_rva(i) + 6 + data_segment;

                    if (data_rva == rva_begin)
                    {
                        vm_iat_calls.emplace_back(pe::stub_import::vm_begin, i);
                        std::printf("%3i %-10i %-s\n", i, parser->fo_to_rva(i), "vm_begin");
                    }
                    else if (data_rva == rva_end)
                    {
                        vm_iat_calls.emplace_back(pe::stub_import::vm_end, i);
                        std::printf("%3i %-10i %-s\n", i, parser->fo_to_rva(i), "vm_end");
                    }
                }
            }
        }
    }

    std::printf("\n");

    // vm macros should be in "begin, end, begin, end" order
    // this is not an entirely reliable way to check because it could mean
    // function A has vm_begin and function B will have vm_end meaning it will
    // virtualize in between the two functions, which should never happen. blame
    // the user

    bool success = true;
    pe::stub_import previous_call = pe::stub_import::vm_end;
    std::ranges::for_each(vm_iat_calls.begin(), vm_iat_calls.end(), [&previous_call, &success](const auto call)
    {
        if (call.first == previous_call)
        {
            success = false;
            return false;
        }

        previous_call = call.first;
        return true;
    });

    if (!success)
    {
        std::printf("[+] failed to verify macro usage\n");
        exit(-1);
    }

    std::printf("[+] successfully verified macro usage\n");

    // to keep relative jumps of the image intact, it is best to just stick the vm
    // section at the back of the pe
    pe::pe_generator generator(parser);
    generator.load_parser();

    std::printf("\n[+] using random seed %llu", util::get_ran_device().seed);
    std::printf("\n[>] generating virtualized code...\n\n");

    std::vector<std::pair<uint32_t, uint32_t>> va_nop;
    std::vector<std::pair<uint32_t, uint32_t>> va_ran;
    std::vector<std::pair<uint32_t, asmb::code_label_ptr>> va_enters;

    asmb::section_manager vm_section(true);
    std::vector<std::shared_ptr<virt::base_machine>> machines_used;


    codec::setup_decoder();
    for (int c = 0; c < vm_iat_calls.size(); c += 2) // i1 = vm_begin, i2 = vm_end
    {
        // we dont want to account for calls if we are parsing by function names
        const uint8_t call_size_64 = parsing_type ? 0 : 6;

        uint32_t rva_inst_begin = parser->fo_to_rva(vm_iat_calls[c].second) + call_size_64;
        uint32_t rva_inst_end = parser->fo_to_rva(vm_iat_calls[c + 1].second);

        std::printf("[+] function %i-%i\n", c, c + 1);
        std::printf("\t[>] instruction begin: 0x%x\n", rva_inst_begin);
        std::printf("\t[>] instruction end: 0x%x\n", rva_inst_end);
        std::printf("\t[>] instruction size: %u\n", rva_inst_end - rva_inst_begin);

        uint8_t* pinst_begin = parser->rva_to_ptr<uint8_t>(rva_inst_begin);
        uint8_t* pinst_end = parser->rva_to_ptr<uint8_t>(rva_inst_end);

        /*
         * this approach is not a good idea, but its easy to solve
         * the problem is that this gives us a limited scope of the context
         * there should be some kind of whole-program context builder because then
         * we will be able to chain every virtualized code section together.
         * but this creates sort of a mess which i dont really like
         */

        dasm::segment_dasm_ptr dasm = std::make_shared<dasm::segment_dasm>(rva_inst_begin, pinst_begin, rva_inst_end - rva_inst_begin);

        std::unordered_map<dasm::basic_block_ptr, uint32_t> bb_discovery_depth;
        std::vector result = dasm->explore_blocks(rva_inst_begin, bb_discovery_depth);

        dasm::analysis::liveness seg_live(dasm);
        seg_live.compute_blocks_use_def();
        seg_live.analyze_cross_liveness(result.back());

        print_liveness(seg_live, dasm->get_blocks());

        std::printf("[>] dasm found %llu basic blocks\n", dasm->get_blocks().size());
        std::cout << std::endl;

        std::shared_ptr ir_trans = std::make_shared<ir::ir_translator>(dasm, &seg_live);
        ir::preopt_block_vec preopt = ir_trans->translate();

        // run some basic pre-optimization passes
        // ir::obfuscator::run_preopt_pass(preopt, &seg_live);

        // here we assign vms to each block
        // for the current example we can assign the same vm id to each block
        uint32_t vm_index = 0;
        std::unordered_map<ir::preopt_block_ptr, uint32_t> block_vm_ids;
        for (const auto& preopt_block : preopt)
            block_vm_ids[preopt_block] = vm_index;

        // we want to prevent the vmenter from being removed from the first block,
        // therefore we mark it as an external call
        ir::preopt_block_ptr entry_block = nullptr;
        for (const auto& preopt_block : preopt)
            if (preopt_block->original_block == dasm->get_block(rva_inst_begin, false))
                entry_block = preopt_block;

        std::unordered_map<ir::block_ptr, uint32_t> ir_estimate_discovery_depth;
        std::vector<std::pair<uint32_t, std::vector<ir::block_ptr>>> block_groups;
        for (const auto& preopt_block : preopt)
        {
            std::vector<ir::block_ptr> block_group;
            VM_ASSERT(bb_discovery_depth.contains(preopt_block->original_block),
                "dissasembly must contain information about original block to map depth");

            auto depth = bb_discovery_depth[preopt_block->original_block];
            ir_estimate_discovery_depth[preopt_block->head] = depth;
            ir_estimate_discovery_depth[preopt_block->tail] = depth;

            for (auto& body : preopt_block->body)
                ir_estimate_discovery_depth[body] = depth;

            block_group.push_back(preopt_block->head);
            block_group.append_range(preopt_block->body);
            block_group.push_back(preopt_block->tail);

            block_groups.emplace_back(depth, block_group);
        }

        VM_ASSERT(entry_block != nullptr, "could not find matching preopt block for entry block");

        // if we want, we can do a little optimzation which will rewrite the preopt
        // blocks, or we could simply ir_trans.flatten()
        std::unordered_map<ir::preopt_block_ptr, ir::block_ptr> block_tracker = { { entry_block, nullptr } };
        std::vector<ir::flat_block_vmid> vm_blocks = ir_trans->optimize(block_vm_ids, block_tracker, { entry_block });


        for (auto& [depth, block_group] : block_groups)
        {
            for (auto it = block_group.begin(); it != block_group.end(); )
            {
                bool found = false;
                for (auto& [blocks_search, vmid] : vm_blocks)
                {
                    for (auto& block_search : blocks_search)
                    {
                        if (*it == block_search)
                        {
                            found = true;
                            break;
                        }
                    }

                    if (found)
                        break;
                }

                if (!found)
                {
                    // delete "block" from "block_group"
                    it = block_group.erase(it);
                }
                else
                {
                    ++it; // Move to the next block
                }
            }
        }

        std::unordered_map<uint32_t, std::vector<ir::block_ptr>> vm_id_map;
        for (auto& [block, vmid] : vm_blocks)
        {
            // while setting up the map we also run the obfuscation pass for handler merging
            vm_id_map[vmid].append_range(block);
        }

        std::vector<ir::block_ptr> alternative_handlers;
        for (auto& blocks : vm_id_map | std::views::values)
        {
            continue;
            std::vector<ir::block_ptr> handler_blocks = ir::obfuscator::create_merged_handlers(blocks);
            blocks.append_range(handler_blocks);

            for (auto& block : handler_blocks)
                ir_estimate_discovery_depth[block] = -1;

            alternative_handlers.append_range(handler_blocks);
            // restore calls, for whatever debug reason
            //for (auto& block : blocks)
            //{
            //    if (block->block_id == 0x5f)
            //        __debugbreak();

            //    for (int i = 0; i < block->size(); i++)
            //    {
            //        if (block->at(i)->get_command_type() == ir::command_type::vm_call)
            //        {
            //            auto call_s = block->get_command<ir::cmd_call>(i);
            //            block->erase(block->begin() + i);

            //            auto target = call_s->get_target();
            //            for (int j = target->size() - 2; j >= 0; j--)
            //                block->insert(block->begin() + i, target->at(j));
            //        }
            //    }
            //}
        }

        // // we want the same settings for every machine
        // virt::pidg::settings_ptr machine_settings =
        // std::make_shared<virt::pidg::settings>();
        // machine_settings->set_temp_count(4);
        // machine_settings->set_randomize_vm_regs(true);
        // machine_settings->set_randomize_stack_regs(true);

        virt::eg::settings_ptr machine_settings = std::make_shared<virt::eg::settings>();
        machine_settings->shuffle_push_order = true;
        machine_settings->shuffle_vm_gpr_order = true;
        machine_settings->shuffle_vm_xmm_order = true;

        // initialize block code labels
        std::unordered_map<ir::block_ptr, asmb::code_label_ptr> block_labels;
        for (auto& blocks : vm_id_map | std::views::values)
            for (const auto& block : blocks)
                block_labels[block] = asmb::code_label::create();

        asmb::code_label_ptr entry_point = asmb::code_label::create();
        for (const auto& blocks : vm_id_map | std::views::values)
        {
            // we create a new machine based off of the same settings to make things
            // more annoying but the same machine could be used :)

            // virt::pidg::machine_ptr machine =
            // virt::pidg::machine::create(machine_settings);
            virt::eg::machine_ptr machine = virt::eg::machine::create(machine_settings);
            machines_used.push_back(machine);

            machine->add_block_context(block_labels);

            for (auto i = 0; i < blocks.size(); i++)
            {
                auto& translated_block = blocks[i];

                asmb::code_container_ptr result_container = machine->lift_block(translated_block);
                ir::block_ptr block = block_tracker[entry_block];
                if (block == translated_block)
                    result_container->bind_start(entry_point);

                vm_section.add_code_container(result_container);
            }

            print_ir_graphviz(block_groups, block_tracker[entry_block], alternative_handlers);

            // build handlers
            std::vector<asmb::code_container_ptr> handler_containers = machine->create_handlers();
            vm_section.add_code_container(handler_containers);
        }

        // overwrite the original instructions
        uint32_t delete_size = vm_iat_calls[c + 1].second - vm_iat_calls[c].second;
        va_ran.emplace_back(parser->fo_to_rva(vm_iat_calls[c].second), delete_size);

        // incase jump goes to previous call, set it to nops
        va_nop.emplace_back(parser->fo_to_rva(vm_iat_calls[c + 1].second), call_size_64);

        // add vmenter for root block
        va_enters.emplace_back(parser->fo_to_rva(vm_iat_calls[c].second), entry_point);
    }

    std::printf("\n");

    win::section_header_t* last_section = parser->get_nt_headers()->get_section(parser->get_nt_headers()->sections().count - 1);

    auto& [code_section, code_section_bytes] = generator.add_section(".hihihi");
    code_section.ptr_raw_data = last_section->ptr_raw_data + last_section->size_raw_data;
    code_section.size_raw_data = 0;
    code_section.virtual_address = generator.align_section(last_section->virtual_address + last_section->virtual_size);
    code_section.virtual_size = generator.align_section(1);

    win::section_characteristics_t characteristics;
    characteristics.mem_read = 1;
    characteristics.mem_execute = 1;
    characteristics.mem_write = 1;
    characteristics.cnt_code = 1;

    code_section.characteristics = characteristics;
    code_section.ptr_relocs = 0;
    code_section.num_relocs = 0;
    code_section.num_line_numbers = 0;

    codec::encoded_vec vm_code_bytes = vm_section.compile_section(code_section.virtual_address);
    code_section.size_raw_data = generator.align_file(vm_code_bytes.size());
    code_section.virtual_size = generator.align_section(vm_code_bytes.size());
    code_section_bytes += vm_code_bytes;

    last_section = &code_section;

    // now that the section is compiled we must:
    // delete the code marked by va_delete
    // create jumps marked by va_enters

    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> va_inserts;
    for (auto& [enter_va, enter_location] : va_enters)
    {
        codec::enc::req jump_request = encode(codec::m_jmp, ZIMMS(enter_location->get_address() - enter_va - 5));
        va_inserts.emplace_back(enter_va, codec::encode_request(jump_request));
    }

    generator.add_ignores(va_nop);
    generator.add_randoms(va_ran);
    generator.add_inserts(va_inserts);
    generator.bake_modifications();

    // custom entry point
    {
        pe::pe_packer packer(&generator);
        packer.set_overlay(false);

        asmb::section_manager packer_sm = packer.create_section();

        auto& [packer_section, packer_bytes] = generator.add_section(".pack");
        packer_section.ptr_raw_data = last_section->ptr_raw_data + last_section->size_raw_data;
        packer_section.size_raw_data = 0;
        packer_section.virtual_address = generator.align_section(last_section->virtual_address + last_section->virtual_size);
        packer_section.virtual_size = generator.align_section(1);
        packer_section.characteristics = characteristics;
        packer_section.ptr_relocs = 0;
        packer_section.num_relocs = 0;
        packer_section.num_line_numbers = 0;

        codec::encoded_vec packer_code_bytes = packer_sm.compile_section(code_section.virtual_address);
        auto [packer_pdb_offset, size] = pe::pe_packer::insert_pdb(packer_code_bytes);

        packer_section.size_raw_data = generator.align_file(packer_code_bytes.size());
        packer_section.virtual_size = generator.align_section(packer_code_bytes.size());
        packer_bytes += packer_code_bytes;

        generator.add_custom_pdb(packer_section.virtual_address + packer_pdb_offset, packer_section.ptr_raw_data + packer_pdb_offset, size);
    }

    std::filesystem::path path(executable);

    std::string target_file_name = path.stem().string() + "_protected" + path.extension().string();
    generator.save_file(target_file_name);
    std::printf("\n[+] generated output file -> %s\n", target_file_name.c_str());

    return 0;
}
