/*
 * titan m2 (acropora, nugget-os) firmware loader for ida pro
 *
 * parses SignedHeader partitions and creates segments:
 *   RO_A  (rx) - read-only firmware region
 *   RW_A  (rx) - read-write firmware region
 *   SRAM  (rw) - zeroed RAM placeholder
 *
 * magic 0xFFFFFFFD - titan m2 (acropora), risc-v 32-bit lol
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include <segment.hpp>
#include <entry.hpp>
#include <bytes.hpp>
#include <name.hpp>

#define MAGIC_M2       0xFFFFFFFDu
#define SIG_HEADER_SIZE 0x400

/*
 * SignedHeader field offsets (little-endian):
 * magic(4) + sig(384) + img_chk(4) + tag(28) + keyid(4) + key(384) = 0x328
 */
#define HDR_OFF_IMAGE_SIZE  (4 + 96*4 + 4 + 7*4 + 4 + 96*4)  /* 0x328 */
#define HDR_OFF_RX_BASE     (HDR_OFF_IMAGE_SIZE + 12)          /* 0x334 */

struct nugget_layout_t {
    const char *chip_name;
    const char *ida_proc;
    uint32_t    flash_half;    /* size of one rot+rw pair */
    uint32_t    ro_size;       /* rot partition size */
    uint32_t    sram_base;
    uint32_t    sram_size;
};

static bool read_u32(linput_t *li, qoff64_t off, uint32_t *out)
{
    qlseek(li, off);
    return qlread(li, out, 4) == 4;
}

static bool detect_layout(linput_t *li, nugget_layout_t *lay)
{
    uint32_t magic;
    if (!read_u32(li, 0, &magic))
        return false;

    if (magic != MAGIC_M2)
        return false;

    lay->chip_name  = "titan m2 (acropora) (risc-v btw)";
    lay->ida_proc   = "riscv:rv32";
    lay->flash_half = 0x80000;
    lay->ro_size    = 0x20000;
    lay->sram_base  = 0x10000;
    lay->sram_size  = 0x10000;
    return true;
}

static bool read_partition_rx_base(linput_t *li, qoff64_t part_off, uint32_t *image_size, uint32_t *rx_base)
{
    if (!read_u32(li, part_off + HDR_OFF_IMAGE_SIZE, image_size)) return false;
    if (!read_u32(li, part_off + HDR_OFF_RX_BASE,   rx_base))    return false;
    return true;
}

static void make_segment(ea_t start, ea_t size, const char *name, const char *cls,
                         uchar perm, uchar bitness)
{
    segment_t s;
    s.start_ea = start;
    s.end_ea   = start + size;
    s.sel      = setup_selector(0);
    s.type     = (perm & SEGPERM_EXEC) ? SEG_CODE : SEG_DATA;
    s.perm     = perm;
    s.bitness  = bitness;
    s.align    = saRelByte;
    s.comb     = scPub;
    add_segm_ex(&s, name, cls, ADDSEG_NOSREG | ADDSEG_OR_DIE);
}

int idaapi accept_file(qstring *fileformatname, qstring *processor,
                       linput_t *li, const char * /*filename*/)
{
    nugget_layout_t lay;
    if (!detect_layout(li, &lay))
        return 0;

    fileformatname->sprnt("Titan M2 nugget-os firmware (%s)", lay.chip_name);
    processor->sprnt("%s", lay.ida_proc);
    return ACCEPT_FIRST;
}

void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{
    nugget_layout_t lay;
    if (!detect_layout(li, &lay))
        loader_failure("Failed to re-detect chip layout");

    inf_set_app_bitness(32);
    set_processor_type(lay.ida_proc, SETPROC_LOADER);

    qoff64_t ro_a_off = 0;
    qoff64_t rw_a_off = lay.ro_size;

    uint32_t ro_img_sz, ro_rx_base;
    uint32_t rw_img_sz, rw_rx_base;

    if (!read_partition_rx_base(li, ro_a_off, &ro_img_sz, &ro_rx_base))
        loader_failure("Cannot read RO_A header");
    if (!read_partition_rx_base(li, rw_a_off, &rw_img_sz, &rw_rx_base))
        loader_failure("Cannot read RW_A header");

    uint32_t ro_code_sz = ro_img_sz - SIG_HEADER_SIZE;
    uint32_t rw_code_sz = rw_img_sz - SIG_HEADER_SIZE;

    ea_t ro_base  = ro_rx_base;
    ea_t rw_base  = rw_rx_base;

    uchar bitness = 1; /* 32bit */

    /* ro_a - read + execute */
    make_segment(ro_base, ro_code_sz, "RO_A", "CODE",
                 SEGPERM_READ | SEGPERM_EXEC, bitness);
    file2base(li, ro_a_off + SIG_HEADER_SIZE,
              ro_base, ro_base + ro_code_sz, FILEREG_PATCHABLE);

    /* rw_a - read + execute */
    make_segment(rw_base, rw_code_sz, "RW_A", "CODE",
                 SEGPERM_READ | SEGPERM_EXEC, bitness);
    file2base(li, rw_a_off + SIG_HEADER_SIZE,
              rw_base, rw_base + rw_code_sz, FILEREG_PATCHABLE);

    /* sram - zeroed placeholder */
    make_segment(lay.sram_base, lay.sram_size, "SRAM", "DATA",
                 SEGPERM_READ | SEGPERM_WRITE, bitness);

    /*
     * da nugget-os rw image has a 0x40-byte firmware header before real code:
     * [+0x00] flags/size
     * [+0x04] ptr -> initial SP value (always rw_base + 0x3C)
     * [+0x08] tagged func ptr
     * [+0x0C] handler ptr
     * [+0x10] null
     * [+0x14] magic 0xCE112233
     * [+0x18] version string (padded to 4 bytes)
     * [+0x3C] initial SP value (SRAM address)
     * [+0x40] actual startup code
     *
     * jst find the code entry by reading ptr at rw_base+0x04, then +4.
     */
    uint32_t sp_ptr_va = 0;
    read_u32(li, rw_a_off + SIG_HEADER_SIZE + 4, &sp_ptr_va);
    ea_t code_entry = (sp_ptr_va != 0 && sp_ptr_va > rw_base && sp_ptr_va < rw_base + rw_code_sz)
                      ? (ea_t)(sp_ptr_va + 4)
                      : rw_base;

    set_name(rw_base, "nugget_rw_header", SN_NOCHECK | SN_FORCE);
    inf_set_start_cs(0);
    inf_set_start_ip(code_entry);
    inf_set_start_ea(code_entry);
    add_entry(code_entry, code_entry, "start", true);

    msg("nugget_ldr: loaded %s\n"
        "  RO_A @ 0x%08X  size 0x%X\n"
        "  RW_A @ 0x%08X  size 0x%X\n"
        "  SRAM @ 0x%08X  size 0x%X\n",
        lay.chip_name,
        (uint32_t)ro_base, ro_code_sz,
        (uint32_t)rw_base, rw_code_sz,
        lay.sram_base, lay.sram_size);
}

idaman loader_t ida_module_data LDSC;

loader_t LDSC = {
    IDP_INTERFACE_VERSION,
    0,
    accept_file,
    load_file,
    nullptr,
    nullptr,
    nullptr,
};
