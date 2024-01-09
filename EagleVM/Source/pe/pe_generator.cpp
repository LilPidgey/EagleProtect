#include "pe/pe_generator.h"

#include <cassert>

void pe_generator::load_parser()
{
    //
    // dos header
    ///
    
    // copy dos header
    PIMAGE_DOS_HEADER existing_dos_header = parser->get_dos_header();
    memcpy(&dos_header, existing_dos_header, sizeof(IMAGE_DOS_HEADER));

    //
    // dos stub
    //
    
    // copy dos stub
    dos_stub = parser->get_dos_stub();

    // remove rich header (TODO)
    // memset(&dos_stub + 0x80, 0, sizeof dos_stub - 0x80);

    //
    // nt header
    //

    // copy nt header
    PIMAGE_NT_HEADERS existing_nt_header = parser->get_nt_header();
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
    std::vector<PIMAGE_SECTION_HEADER> existing_sections = parser->get_sections();
    for (PIMAGE_SECTION_HEADER section : existing_sections)
    {
        std::vector<uint8_t> data(section->SizeOfRawData, 0);
        memcpy(data.data(), parser->get_base() + section->PointerToRawData, section->SizeOfRawData);

        sections.push_back({ *section, data });
    }
}

generator_section_t& pe_generator::add_section(const char* name)
{
    generator_section_t new_section = {};
    auto& section_name = std::get<0>(new_section).Name;
    auto name_length = strlen(name);
    for (size_t i = 0; i < (std::min)(_countof(section_name), name_length); i++)
    {
        section_name[i] = name[i];
    }
    
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

std::vector<generator_section_t> pe_generator::get_sections()
{
    return sections;
}

generator_section_t& pe_generator::get_last_section()
{
    return sections.back();
}

static std::string section_name(const IMAGE_SECTION_HEADER& section)
{
    // NOTE: the section.Name is not guaranteed to be null-terminated
    char name[sizeof(section.Name) + 1] = {};
    memcpy(name, section.Name, sizeof(section.Name));
    return name;
}

void pe_generator::save_file(const std::string& save_path)
{
    // account for binaries potentially placing sections in a different order virtually
    // NOTE: this isn't actually allowed by the spec and these binaries wouldn't load
    std::sort(sections.begin(), sections.end(), [](auto& a, auto& b)
        {
            auto a_section = std::get<0>(a);
            auto b_section = std::get<0>(b);

            return a_section.VirtualAddress < b_section.VirtualAddress;
        });

    auto last_section = std::get<0>(sections.back());
    uint32_t binary_virtual_size = last_section.VirtualAddress + last_section.Misc.VirtualSize;

    printf("[+] section alignment: 0x%X, file alignment: 0x%X\n",
        nt_headers.OptionalHeader.SectionAlignment,
        nt_headers.OptionalHeader.FileAlignment
    );

    // update nt headers
    nt_headers.OptionalHeader.SizeOfImage = align_section(binary_virtual_size);
    nt_headers.FileHeader.NumberOfSections = (uint16_t)sections.size();

    const auto header_size = align_file((uint32_t)(
        sizeof(dos_header) +
        dos_stub.size() +
        sizeof(nt_headers) +
        sections.size() * sizeof(IMAGE_SECTION_HEADER)
        ));

    if (header_size > nt_headers.OptionalHeader.SizeOfHeaders)
    {
        printf("[!] adjusting sections to grow header (0x%X -> 0x%X)\n",
            nt_headers.OptionalHeader.SizeOfHeaders,
            header_size
        );

        const auto delta = header_size - nt_headers.OptionalHeader.SizeOfHeaders;
        nt_headers.OptionalHeader.SizeOfHeaders = header_size;
        for (auto& [section, _] : sections)
        {
            // TODO: confirm that there are no file offsets used in any of the data directories
            section.PointerToRawData += delta;
        }
    }

    // write the headers to the file
    std::ofstream protected_binary(save_path, std::ios::binary);
    protected_binary.write((char*)&dos_header, sizeof(dos_header));
    protected_binary.write((char*)dos_stub.data(), dos_stub.size());
    protected_binary.write((char*)&nt_headers, sizeof(nt_headers));
    for (auto& [section, data] : sections)
    {
        auto name = section_name(section);
        const auto aligned_offset = align_file(section.PointerToRawData);
        if (aligned_offset != section.PointerToRawData)
        {
            printf("[!] section %s has invalid offset alignment -> 0x%X (adjusting)\n",
                name.c_str(),
                section.PointerToRawData
            );
            section.PointerToRawData = aligned_offset;
        }
        const auto aligned_size = align_file(section.SizeOfRawData);
        if (aligned_size != section.SizeOfRawData)
        {
            printf("[!] section %s has invalid size alignment -> 0x%X (adjusting)\n",
                name.c_str(),
                section.SizeOfRawData
            );
            section.SizeOfRawData = aligned_size;
        }
        const auto data_size = (uint32_t)data.size();
        const auto aligned_data_size = align_file(data_size);
        if (aligned_size != aligned_data_size)
        {
            printf("[!] section %s size (0x%X) inconsistent with data size (0x%X -> 0x%X)\n",
                name.c_str(),
                aligned_size,
                data_size,
                aligned_data_size
            );
            __debugbreak();
        }
        if (section.Misc.VirtualSize == 0)
        {
            printf("[!] section %s has virtual size of 0\n",
                name.c_str()
            );
        }
        protected_binary.write((char*)&section, sizeof(section));
    }

    // sort the sections by file offset to emit them in file order
    std::sort(sections.begin(), sections.end(), [](auto& a, auto& b)
        {
            auto a_section = std::get<0>(a);
            auto b_section = std::get<0>(b);

            return a_section.PointerToRawData < b_section.PointerToRawData;
        });

    // make sure the header is padded correctly
    assert(protected_binary.tellp() <= header_size);
    if (protected_binary.tellp() >= header_size)
    {
        printf("[!] header size adjustment went wrong...\n");
        __debugbreak();
    }
    protected_binary.seekp(header_size, std::ios::beg);

    for (auto& [section, data] : sections)
    {
        // sanity checks
        const auto current_offset = (uint32_t)protected_binary.tellp();
        printf("[+] section %s -> 0x%X bytes (current offset: 0x%X)\n",
            section_name(section).c_str(),
            section.SizeOfRawData,
            current_offset
        );
        if (current_offset != section.PointerToRawData)
        {
            printf("[!] expected file offset 0x%X, got 0x%X\n", section.PointerToRawData, current_offset);
            __debugbreak();
        }

        if (data.empty())
        {
            continue;
        }

        // write the data
        printf("    writing 0x%zX data bytes\n", data.size());
        protected_binary.write((char*)data.data(), data.size());

        // align the section
        const auto padding_size = (uint32_t)section.SizeOfRawData - (uint32_t)data.size();
        if (padding_size > 0)
        {
            printf("    writing 0x%X padding bytes\n", padding_size);
            std::vector<char> padding(padding_size);
            protected_binary.write(padding.data(), padding.size());
        }
    }
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
