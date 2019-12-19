const std = @import("std");
const elf = std.elf;
const mem = std.mem;
const assert = std.debug.assert;

fn push_string(strings: []u8, index: *usize, string: [] const u8) usize {
    const result = index.*;
    mem.copy(u8, strings[index.* ..], string);
    index.* += string.len;
    strings[index.*] = 0;
    index.* += 1;
    return result;
}

pub fn main() anyerror!void {
    const entry_addr = 0x1337000;
    const target = std.Target.current;
    const ptr_width: enum {
        _32,
        _64,
    } = switch (target.getArchPtrBitWidth()) {
        32 => ._32,
        64 => ._64,
        else => return error.UnsupportedArchitecture,
    };

    var string_buf: [100]u8 = undefined;
    var string_offset: usize = 0;
    const null_index = push_string(&string_buf, &string_offset, "");
    const strtab_index = push_string(&string_buf, &string_offset, ".shstrtab");
    const symtab_index = push_string(&string_buf, &string_offset, ".symtab");
    const text_index = push_string(&string_buf, &string_offset, ".text");
    const start_index = push_string(&string_buf, &string_offset, "_start");

    const endian = target.getArch().endian();
    const end_of_program_header_offset = @sizeOf(elf.Elf64_Ehdr) + @sizeOf(elf.Elf64_Phdr);
    const sections = 4;
    var hdr_buf: [end_of_program_header_offset + @sizeOf(elf.Elf64_Shdr) * sections]u8 = undefined;
    var index: usize = 0;

    mem.copy(u8, hdr_buf[index..], "\x7fELF");
    index += 4;

    hdr_buf[index] = switch (ptr_width) {
        ._32 => 1,
        ._64 => 2,
    };
    index += 1;

    hdr_buf[index] = switch (endian) {
        .Little => 1,
        .Big => 2,
    };
    index += 1;

    hdr_buf[index] = 1; // ELF version
    index += 1;

    // OS ABI, often set to 0 regardless of target platform
    // ABI Version, possibly used by glibc but not by static executables
    // padding
    mem.set(u8, hdr_buf[index..][0..9], 0);
    index += 9;

    assert(index == 16);

    // TODO: https://github.com/ziglang/zig/issues/863 makes this (and all following) @ptrCast unnecessary
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), @enumToInt(elf.ET.EXEC), endian);
    index += 2;

    const machine = target.getArch().toElfMachine();
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), @enumToInt(machine), endian);
    index += 2;

    // ELF Version, again
    mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), 1, endian);
    index += 4;

    switch (ptr_width) {
        ._32 => {
            unreachable;
        },
        ._64 => {
            // e_entry
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), entry_addr, endian);
            index += 8;

            // e_phoff
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), @sizeOf(elf.Elf64_Ehdr), endian);
            index += 8;

            // e_shoff
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), end_of_program_header_offset, endian);
            index += 8;
        },
    }

    const e_flags = 0;
    mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), e_flags, endian);
    index += 4;

    const e_ehsize: u16 = switch (ptr_width) {
        ._32 => @sizeOf(elf.Elf32_Ehdr),
        ._64 => @sizeOf(elf.Elf64_Ehdr),
    };
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_ehsize, endian);
    index += 2;

    const e_phentsize: u16 = switch (ptr_width) {
        ._32 => @sizeOf(elf.Elf32_Phdr),
        ._64 => @sizeOf(elf.Elf64_Phdr),
    };
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_phentsize, endian);
    index += 2;

    const e_phnum = 1;
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_phnum, endian);
    index += 2;

    const e_shentsize: u16 = switch (ptr_width) {
        ._32 => @sizeOf(elf.Elf32_Shdr),
        ._64 => @sizeOf(elf.Elf64_Shdr),
    };
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_shentsize, endian);
    index += 2;

    const e_shnum = sections;
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_shnum, endian);
    index += 2;

    const e_shstrndx = 1;
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_shstrndx, endian);
    index += 2;

    assert(index == e_ehsize);

    // Program header

    const p_type = elf.PT_LOAD;
    mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), p_type, endian);
    index += 4;

    const machine_code = [_]u8{
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 0x3c
        0x31, 0xff, // xor edi, edi
            0x0f, 0x05, // syscall
    };

    const zeroes = [1]u8{0} ** 0x1000;

    const unaligned = hdr_buf.len + string_offset;
    const symbol_table_sh_align = 8;
    const symbol_table_sh_offset = mem.alignForward(unaligned, symbol_table_sh_align);
    const symbol_table_padding = symbol_table_sh_offset - unaligned;
    const symbol_entries = 2;
    const end_of_shit = symbol_table_sh_offset + symbol_entries * @sizeOf(elf.Elf64_Sym);
    const p_offset = mem.alignForward(end_of_shit, 0x1000);
    const pad = p_offset - end_of_shit;
    switch (ptr_width) {
        ._32 => @panic("TODO"),
        ._64 => {

            const p_flags = elf.PF_X | elf.PF_R;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), p_flags, endian);
            index += 4;

            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), p_offset, endian);
            index += 8;

            const p_vaddr = entry_addr;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), p_vaddr, endian);
            index += 8;

            const p_paddr = entry_addr;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), p_paddr, endian);
            index += 8;

            const p_filesz = machine_code.len;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), p_filesz, endian);
            index += 8;

            const p_memsz = machine_code.len;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), p_memsz, endian);
            index += 8;

            const p_align = 0x1000;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), p_align, endian);
            index += 8;

            assert(index == end_of_program_header_offset);
        },
        else => unreachable,
    }

    // Write section headers
    {
        // Null
        {
            const sh_name = 0;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_name, endian);
            index += 4;

            const sh_type = elf.SHT_NULL;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_type, endian);
            index += 4;

            const sh_flags = 0;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_flags, endian);
            index += 8;

            const sh_addr = 0;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_addr, endian);
            index += 8;

            const sh_offset = 0;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_offset, endian);
            index += 8;

            const sh_size = 0;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_size, endian);
            index += 8;

            const sh_link = 0;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_link, endian);
            index += 4;

            const sh_info = 0;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_info, endian);
            index += 4;

            const sh_align = 0;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_align, endian);
            index += 8;

            const sh_entsize = 0;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_entsize, endian);
            index += 8;
        }

        // Strings
        {
            const sh_name = @intCast(u32, strtab_index);
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_name, endian);
            index += 4;

            const sh_type = elf.SHT_STRTAB;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_type, endian);
            index += 4;

            const sh_flags = 0;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_flags, endian);
            index += 8;

            const sh_addr = 0;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_addr, endian);
            index += 8;

            const sh_offset = hdr_buf.len;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_offset, endian);
            index += 8;

            const sh_size = string_offset;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_size, endian);
            index += 8;

            const sh_link = 0;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_link, endian);
            index += 4;

            const sh_info = 0;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_info, endian);
            index += 4;

            const sh_align = 1;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_align, endian);
            index += 8;

            const sh_entsize = 0;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_entsize, endian);
            index += 8;
        }

        // Text
        {
            const sh_name = @intCast(u32, text_index);
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_name, endian);
            index += 4;

            const sh_type = elf.SHT_PROGBITS;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_type, endian);
            index += 4;

            const sh_flags = elf.SHF_ALLOC | elf.SHF_EXECINSTR;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_flags, endian);
            index += 8;

            const sh_addr = entry_addr;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_addr, endian);
            index += 8;

            const sh_offset = p_offset;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_offset, endian);
            index += 8;

            const sh_size = machine_code.len;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_size, endian);
            index += 8;

            const sh_link = 0;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_link, endian);
            index += 4;

            const sh_info = 0;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_info, endian);
            index += 4;

            const sh_align = 0x1000;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_align, endian);
            index += 8;

            const sh_entsize = 0;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_entsize, endian);
            index += 8;
        }

        // Symbol table
        {
            const sh_name = @intCast(u32, symtab_index);
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_name, endian);
            index += 4;

            const sh_type = elf.SHT_SYMTAB;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_type, endian);
            index += 4;

            const sh_flags = 0;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_flags, endian);
            index += 8;

            const sh_addr = 0;
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_addr, endian);
            index += 8;

            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), symbol_table_sh_offset, endian);
            index += 8;

            const sh_size = symbol_entries * @sizeOf(elf.Elf64_Sym);
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_size, endian);
            index += 8;

            const sh_link = 1;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_link, endian);
            index += 4;

            const sh_info = 2;
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), sh_info, endian);
            index += 4;

            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), symbol_table_sh_align, endian);
            index += 8;

            const sh_entsize = @sizeOf(elf.Elf64_Sym);
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), sh_entsize, endian);
            index += 8;
        }
    }

    assert(index == hdr_buf.len);

    const file = try std.fs.File.openWriteMode("output", 0o755);
    defer file.close();

    const out = &file.outStream().stream;

    try file.write(hdr_buf[0..index]);
    try file.write(string_buf[0..string_offset]);
    assert(symbol_entries == 2);
    try file.write(zeroes[0..symbol_table_padding]);
    try writeStruct(out, elf.Elf64_Sym, elf.Elf64_Sym {
        .st_name = 0,
        .st_info = 0,
        .st_other = 0,
        .st_shndx = 0,
        .st_value = 0,
        .st_size = 0,
    });
    try writeStruct(out, elf.Elf64_Sym, elf.Elf64_Sym {
        .st_name = @intCast(u32, start_index),
        .st_info = (elf.STB_LOCAL << 4) | elf.STT_FUNC,
        .st_other = 0,
        .st_shndx = 2,
        .st_value = entry_addr,
        .st_size = machine_code.len,
    });
    try file.write(zeroes[0..pad]);
    try file.write(&machine_code);
}

pub fn writeStruct(self: var, comptime T: type, value: T) !void {
    comptime assert(@typeInfo(T).Struct.layout != .Auto);
    return self.writeFn(self, @ptrCast([*] const u8, &value)[0..@sizeOf(T)]);
}
