#include "eaglevm-core/pe/pe_generator.h"

#include <cassert>
#include <ranges>

#include "eaglevm-core/util/random.h"
#include "eaglevm-core/util/assert.h"

namespace eagle::pe
{
    void pe_generator::load_parser()
    {
        //
        // dos header
        ///

        // copy dos header
        const auto existing_dos_header = parser->get_dos_headers();
        memcpy(&dos_header, existing_dos_header, sizeof(IMAGE_DOS_HEADER));

        //
        // dos stub
        //

        // copy dos stub
        const uint8_t* start = reinterpret_cast<uint8_t*>(parser->get_dos_headers()) + sizeof(IMAGE_DOS_HEADER);
        const uint8_t* end = reinterpret_cast<uint8_t*>(parser->get_nt_headers());
        dos_stub = std::vector<uint8_t>(end - start, 0);
        std::copy(start, end, dos_stub.begin());

        // remove rich header (TODO)
        // memset(&dos_stub + 0x80, 0, sizeof dos_stub - 0x80);

        //
        // nt header
        //

        // copy nt header
        const auto existing_nt_header = parser->get_nt_headers();
        memcpy(&nt_headers, existing_nt_header, sizeof(IMAGE_NT_HEADERS));

        // signature

        // file header
        IMAGE_FILE_HEADER* file = &nt_headers.FileHeader;
        file->TimeDateStamp = 0;

        // optional header
        IMAGE_OPTIONAL_HEADER* optional = &nt_headers.OptionalHeader;
        optional->MajorImageVersion = UINT16_MAX;
        optional->MinorImageVersion = UINT16_MAX;
        optional->SizeOfStackCommit += 20 * 8;

        //
        // section headers
        //

        // copy section headers
        for (win::section_header_t section : parser->get_nt_headers()->sections())
        {
            std::vector<uint8_t> data(section.size_raw_data, 0);
            memcpy(data.data(), parser->raw_to_ptr(section.ptr_raw_data), section.size_raw_data);

            sections.emplace_back(section, data);
        }

        // shitty fix but this should stop references from getting reallocated
        sections.reserve(sections.size() + 3);
    }

    generator_section_t& pe_generator::add_section(const char* name)
    {
        generator_section_t new_section = { };
        for (auto i = 0; i < strlen(name); i++)
            new_section.first.name.short_name[i] = name[i];

        sections.push_back(new_section);
        nt_headers.FileHeader.NumberOfSections++;

        return sections.back();
    }

    void pe_generator::add_section(const PIMAGE_SECTION_HEADER section_header)
    {
        // section_headers.push_back(*section_header);
    }

    void pe_generator::add_section(const IMAGE_SECTION_HEADER section_header)
    {
        // section_headers.push_back(section_header);
    }

    void pe_generator::add_ignores(const std::vector<std::pair<uint32_t, uint32_t>>& ignore)
    {
        va_ignore = ignore;
    }

    void pe_generator::add_randoms(const std::vector<std::pair<uint32_t, uint32_t>>& random)
    {
        va_random = random;
    }

    void pe_generator::add_inserts(std::vector<std::pair<uint32_t, std::vector<uint8_t>>>& insert)
    {
        va_insert = insert;
    }

    void pe_generator::bake_modifications()
    {
        for (auto& [section, data] : sections)
        {
            // calculate the start and end virtual addresses of the section
            uint32_t section_start_va = section.virtual_address;
            uint32_t section_end_va = section_start_va + section.virtual_size;

            // iterate over va_ignore
            for (auto& [va, bytes] : va_ignore)
            {
                if (va >= section_start_va && va < section_end_va)
                {
                    // calculate the offset within the section data
                    const uint32_t offset = va - section_start_va;

                    // replace the bytes at the offset with 0x90
                    std::fill_n(data.begin() + offset, bytes, 0x90);
                }
            }

            for (auto& [va, bytes] : va_random)
            {
                if (va >= section_start_va && va < section_end_va)
                {
                    // calculate the offset within the section data
                    const uint32_t offset = va - section_start_va;

                    // replace the bytes at the offset with 0x90
                    std::generate_n(data.begin() + offset, bytes, [&]
                    {
                        return util::ran_device::get().gen_8();
                    });
                }
            }

            // iterate over va_insert
            for (auto& [va, bytes_to_insert] : va_insert)
            {
                if (va >= section_start_va && va < section_end_va)
                {
                    // calculate the offset within the section data
                    const uint32_t offset = va - section_start_va;

                    // replace the bytes at the offset with the bytes from the vector
                    std::ranges::copy(bytes_to_insert, data.begin() + offset);
                }
            }
        }
    }

    std::vector<generator_section_t>& pe_generator::get_sections()
    {
        return sections;
    }

    generator_section_t& pe_generator::get_last_section()
    {
        return sections.back();
    }

    void pe_generator::remove_section(const char* section_name)
    {
        std::erase_if(sections, [section_name](const auto& section)
        {
            const win::section_header_t pe = std::get<0>(section);
            return pe.name.equals(section_name);
        });

        // make sure sections are properly sorted before updating raw offsets
        std::ranges::sort(sections, [](auto& a, auto& b)
        {
            auto a_section = std::get<0>(a);
            auto b_section = std::get<0>(b);

            return a_section.ptr_raw_data < b_section.ptr_raw_data;
        });

        // walk each section in "sections and upddate the PointerToRawData so that there are not gaps between the previous section
        uint32_t current_offset = std::get<0>(sections.front()).ptr_raw_data;
        for (auto& section : sections | std::views::keys)
        {
            section.ptr_raw_data = current_offset;
            current_offset += align_file(section.size_raw_data);
        }
    }

    std::string pe_generator::section_name(const IMAGE_SECTION_HEADER& section)
    {
        // NOTE: the section.Name is not guaranteed to be null-terminated
        char name[sizeof(section.Name) + 1] = { };
        memcpy(name, section.Name, sizeof(section.Name));
        return name;
    }

    void pe_generator::save_file(const std::string& save_path)
    {
        // account for binaries potentially placing sections in a different order virtually
        // NOTE: this isn't actually allowed by the spec and these binaries wouldn't load
        std::ranges::sort(sections, [](auto& a, auto& b)
        {
            auto a_section = std::get<0>(a);
            auto b_section = std::get<0>(b);

            return a_section.virtual_address < b_section.virtual_address;
        });

        auto last_section = std::get<0>(sections.back());
        uint32_t binary_virtual_size = last_section.virtual_address + last_section.virtual_size;

        printf("[+] section alignment: 0x%lu, file alignment: 0x%lu\n",
            nt_headers.OptionalHeader.SectionAlignment,
            nt_headers.OptionalHeader.FileAlignment
        );

        // update nt headers
        nt_headers.OptionalHeader.SizeOfImage = align_section(binary_virtual_size);
        nt_headers.FileHeader.NumberOfSections = static_cast<uint16_t>(sections.size());

        const auto header_size = align_file(
            sizeof(dos_header) +
            dos_stub.size() +
            sizeof(nt_headers) +
            sections.size() * sizeof(IMAGE_SECTION_HEADER)
        );

        if (header_size > nt_headers.OptionalHeader.SizeOfHeaders)
        {
            printf("[!] adjusting sections to grow header (0x%lu -> 0x%X)\n",
                nt_headers.OptionalHeader.SizeOfHeaders,
                header_size
            );

            const auto delta = header_size - nt_headers.OptionalHeader.SizeOfHeaders;
            nt_headers.OptionalHeader.SizeOfHeaders = header_size;

            for (auto& section : sections | std::views::keys)
            {
                // TODO: confirm that there are no file offsets used in any of the data directories
                section.ptr_raw_data += delta;
            }
        }

        // write the headers to the file
        std::ofstream protected_binary(save_path, std::ios::binary);
        protected_binary.write(reinterpret_cast<char*>(&dos_header), sizeof(dos_header));
        protected_binary.write(reinterpret_cast<char*>(dos_stub.data()), dos_stub.size());
        protected_binary.write(reinterpret_cast<char*>(&nt_headers), sizeof(nt_headers));

        for (auto& [section, data] : sections)
        {
            auto name = section.name.to_string();
            const auto aligned_offset = align_file(section.ptr_raw_data);

            if (aligned_offset != section.ptr_raw_data)
            {
                printf("[!] section %s has invalid offset alignment -> 0x%X (adjusting)\n",
                    name.data(),
                    section.ptr_raw_data
                );

                section.ptr_raw_data = aligned_offset;
            }

            const auto aligned_size = align_file(section.size_raw_data);
            if (aligned_size != section.size_raw_data)
            {
                printf("[!] section %s has invalid size alignment -> 0x%X (adjusting)\n",
                    name.data(),
                    section.size_raw_data
                );

                section.size_raw_data = aligned_size;
            }

            const auto data_size = static_cast<uint32_t>(data.size());
            const auto aligned_data_size = align_file(data_size);
            if (aligned_size != aligned_data_size)
            {
                printf("[!] section %s size (0x%X) inconsistent with data size (0x%X -> 0x%X)\n",
                    name.data(),
                    aligned_size,
                    data_size,
                    aligned_data_size
                );

                __debugbreak();
            }

            if (section.virtual_size == 0)
            {
                printf("[!] section %s has virtual size of 0\n",
                    name.data()
                );
            }

            protected_binary.write(reinterpret_cast<char*>(&section), sizeof(section));
        }

        // sort the sections by file offset to emit them in file order
        std::ranges::sort(sections, [](auto& a, auto& b)
        {
            auto a_section = std::get<0>(a);
            auto b_section = std::get<0>(b);

            return a_section.ptr_raw_data < b_section.ptr_raw_data;
        });

        // make sure the header is padded correctly
        VM_ASSERT(protected_binary.tellp() <= header_size);
        if (protected_binary.tellp() >= header_size)
        {
            printf("[!] header size adjustment went wrong...\n");
            __debugbreak();
        }
        protected_binary.seekp(header_size, std::ios::beg);

        for (auto& [section, data] : sections)
        {
            // sanity checks
            const auto current_offset = static_cast<uint32_t>(protected_binary.tellp());
            printf("[+] section %s -> 0x%X bytes (current offset: 0x%X)\n",
                section.name.to_string().data(),
                section.size_raw_data,
                current_offset
            );

            if (current_offset != section.ptr_raw_data)
            {
                printf("[!] expected file offset 0x%X, got 0x%X\n", section.ptr_raw_data, current_offset);
                __debugbreak();
            }

            if (data.empty())
            {
                continue;
            }

            // write the data
            printf("    writing 0x%zX data bytes\n", data.size());
            protected_binary.write(reinterpret_cast<char*>(data.data()), data.size());

            // align the section
            const auto padding_size = section.size_raw_data - static_cast<uint32_t>(data.size());
            if (padding_size > 0)
            {
                printf("    writing 0x%X padding bytes\n", padding_size);
                std::vector<char> padding(padding_size);
                protected_binary.write(padding.data(), padding.size());
            }
        }
    }

    void pe_generator::zero_memory_rva(uint32_t rva, const uint32_t size)
    {
        // find section where rva is located
        auto section = std::ranges::find_if(sections, [rva](const auto& section)
        {
            auto section_start = std::get<0>(section).virtual_address;
            auto section_end = section_start + std::get<0>(section).virtual_size;

            return rva >= section_start && rva < section_end;
        });

        uint32_t offset = rva - std::get<0>(*section).virtual_address;
        std::vector<uint8_t>& section_buffer = std::get<1>(*section);

        std::fill_n(section_buffer.begin() + offset, size, 0);
    }

    static uint32_t align_up(uint32_t value, uint32_t alignment)
    {
        auto mask = alignment - 1;
        return (value + mask) & ~mask;
    }

    uint32_t pe_generator::align_section(uint32_t value) const
    {
        return align_up(value, nt_headers.OptionalHeader.SectionAlignment);
    }

    uint32_t pe_generator::align_file(uint32_t value) const
    {
        return align_up(value, nt_headers.OptionalHeader.FileAlignment);
    }

    void pe_generator::add_custom_pdb(uint32_t target_rva, uint32_t target_raw, uint32_t target_size)
    {
        const IMAGE_DATA_DIRECTORY debug_data = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (debug_data.Size == 0)
            return;

        // given debug_data.VirtualAddress enumerate sections to find the section that contains the debug data
        for (auto& [section, data] : sections)
        {
            const uint32_t section_start_va = section.virtual_address;
            const uint32_t section_end_va = section_start_va + section.virtual_size;

            if (debug_data.VirtualAddress >= section_start_va && debug_data.VirtualAddress < section_end_va)
            {
                uint32_t debug_data_rva = debug_data.VirtualAddress;
                uint32_t debug_data_offset = debug_data_rva - section_start_va;

                const auto debug_dir = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(data.data() + debug_data_offset);
                for (int i = 0; i < debug_data.Size / sizeof(IMAGE_DEBUG_DIRECTORY); i++)
                {
                    IMAGE_DEBUG_DIRECTORY* debug_entry = &debug_dir[i];
                    if (debug_entry->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
                        continue;

                    uint8_t* pdb_data = data.data() + debug_entry->PointerToRawData - section.ptr_raw_data;
                    memset(pdb_data, 0, debug_entry->SizeOfData);

                    debug_entry->PointerToRawData = target_raw;
                    debug_entry->AddressOfRawData = target_rva;
                    debug_entry->SizeOfData = target_size;
                    break;
                }

                break;
            }
        }
    }
}
