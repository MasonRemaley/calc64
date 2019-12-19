const std = @import("std");
const elf = std.elf;
const mem = std.mem;
const assert = std.debug.assert;

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

    const endian = target.getArch().endian();
    var hdr_buf: [@sizeOf(elf.Elf64_Ehdr) + @sizeOf(elf.Elf64_Phdr)]u8 = undefined;
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
            // e_entry
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), @intCast(u32, entry_addr), endian);
            index += 4;

            // e_phoff
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), @sizeOf(elf.Elf32_Ehdr), endian);
            index += 4;

            // e_shoff
            mem.writeInt(u32, @ptrCast(*[4]u8, &hdr_buf[index]), 0, endian);
            index += 4;
        },
        ._64 => {
            // e_entry
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), entry_addr, endian);
            index += 8;

            // e_phoff
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), @sizeOf(elf.Elf64_Ehdr), endian);
            index += 8;

            // e_shoff
            mem.writeInt(u64, @ptrCast(*[8]u8, &hdr_buf[index]), 0, endian);
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

    const e_shnum = 0;
    mem.writeInt(u16, @ptrCast(*[2]u8, &hdr_buf[index]), e_shnum, endian);
    index += 2;

    const e_shstrndx = 0;
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
    var pad: usize = undefined;

    switch (ptr_width) {
        ._32 => @panic("TODO"),
        ._64 => {
            const phdr_end = @sizeOf(elf.Elf64_Ehdr) + @sizeOf(elf.Elf64_Phdr);
            const p_offset = mem.alignForward(phdr_end, 0x1000);
            pad = p_offset - phdr_end;

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

            assert(index == phdr_end);
        },
        else => unreachable,
    }

    const file = try std.fs.File.openWriteMode("output", 0o755);
    defer file.close();
    try file.write(hdr_buf[0..index]);
    try file.write(zeroes[0..pad]);
    try file.write(&machine_code);
}
