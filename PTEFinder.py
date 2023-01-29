import gdb


class Pte(gdb.Command):
    def __init__(self):
        super().__init__(
            'pte',
            gdb.COMMAND_BREAKPOINTS,
            gdb.COMPLETE_NONE,
            False
        )

    def invoke(self, arg, from_tty):
        if arg is None or len(arg) < 0:
            self.print_usage_error()
            return
        arguments = arg.split(" ")
        if len(arguments) > 2:
            self.print_usage_error()
            return

        virt_addr = int(arguments[0], 16)
        if len(arguments) == 2:
            cr3 = int(arguments[1],16)
        else:
            cr3 = int(gdb.parse_and_eval("$cr3"))

        

        gdb.execute("maintenance packet Qqemu.PhyMemMode:1", to_string = True)


        PML4_addr = self.get_bits(cr3, 47, 12) << 12
        PML4_offset = self.get_bits(virt_addr, 47, 39) * 8
        PML4_entry = int(gdb.execute("x/gx {0}".format(PML4_addr + PML4_offset), to_string = True).split("\t")[-1], 16)
        flags, PDPT_addr = self.unmarshall_PML4_entry(PML4_entry)

        print("PML4 addr:\t{0}\tPML4 entry:\t{1} {2}".format(hex(PML4_addr), hex(PML4_entry), flags))

        PDPT_offset = self.get_bits(virt_addr, 38, 30) * 8 
        PDPT_entry = int(gdb.execute("x/gx {0}".format(PDPT_addr + PDPT_offset), to_string = True).split("\t")[-1], 16)
        
        flags, PD_addr = self.unmarshall_PDPT_entry(PDPT_entry)

        print("PDPT addr:\t{0}\tPDPT entry:\t{1} {2}".format(hex(PDPT_addr), hex(PDPT_entry), flags))

        PD_offset = self.get_bits(virt_addr, 29,21) * 8
        PD_entry = int(gdb.execute("x/gx {0}".format(PD_addr + PD_offset), to_string = True).split("\t")[-1], 16)

        flags, PT_addr = self.unmarshall_PD_entry(PD_entry)

        print("PD addr:\t{0}\tPD entry:\t{1} {2}".format(hex(PD_addr), hex(PD_entry), flags))

        PT_offset = self.get_bits(virt_addr, 20, 12) * 8
        PT_entry = int(gdb.execute("x/gx {0}".format(PT_addr + PT_offset), to_string = True).split("\t")[-1], 16)

        flags, P_addr = self.unmarshall_PT_entry(PT_entry)
        P_offset = self.get_bits(virt_addr, 11, 0)

        print("PT addr:\t{0}\tPT entry:\t{1} {2}".format(hex(PT_addr), hex(PT_entry), flags))

        print("Physical addr:\t{0}".format(hex(P_addr+P_offset)))
        
        gdb.execute("maintenance packet Qqemu.PhyMemMode:0", to_string = True)


    def unmarshall_PML4_entry(self, value):
        present = self.get_bits(value, 0, 0)
        rw = self.get_bits(value, 1, 1)
        us = self.get_bits(value, 2, 2)
        pwt = self.get_bits(value, 3, 3)
        pcd = self.get_bits(value, 4, 4)
        accessed = self.get_bits(value, 5, 5)
        physical_addr = self.get_bits(value, 51, 12) << 12
        nx = self.get_bits(value, 63, 63)
        
        flags = []

        if present == 1:
            flags.append("P") # Present
        if rw == 1:
            flags.append("RW") # Read-write
        if us == 1:
            flags.append("S") # Supervisor
        if pwt == 1:
            flags.append("PWT") # Page-level write-through bit. This bit controls whether the write-through caching policy is enabled (1) or disabled (0) for the corresponding page table
        if pcd == 1:
            flags.append("PCD") #  Page-level cache disable bit.
        if accessed == 1:
            flags.append("A") # Has it been accessed?
        if nx == 1:
            flags.append("NX") # non-execute

        flags_str = "[" + " ".join(flags) + "]"

        return (flags_str, physical_addr)

    def unmarshall_PDPT_entry(self, value):
        present = self.get_bits(value, 0, 0)
        rw = self.get_bits(value, 1, 1)
        us = self.get_bits(value, 2, 2)
        pwt = self.get_bits(value, 3, 3)
        pcd = self.get_bits(value, 4, 4)
        accessed = self.get_bits(value, 5, 5)
        page_size = self.get_bits(value, 7, 7)
        physical_addr = self.get_bits(value, 51, 12) << 12

        flags = []

        if present == 1:
            flags.append("P") # Present
        if rw == 1:
            flags.append("RW") # Read-write
        if us == 1:
            flags.append("S") # Supervisor
        if pwt == 1:
            flags.append("PWT") # Page-level write-through bit. This bit controls whether the write-through caching policy is enabled (1) or disabled (0) for the corresponding page table
        if pcd == 1:
            flags.append("PCD") #  Page-level cache disable bit.
        if accessed == 1:
            flags.append("A") # Has it been accessed?
        if page_size == 1:
            flags.append("PS") # page size. 4 kb or 2 mb?

        flags_str = "[" + " ".join(flags) + "]"

        return (flags_str, physical_addr)


    def unmarshall_PD_entry(self, value):
        present = self.get_bits(value, 0, 0)
        rw = self.get_bits(value, 1, 1)
        us = self.get_bits(value, 2, 2)
        pwt = self.get_bits(value, 3, 3)
        pcd = self.get_bits(value, 4, 4)
        accessed = self.get_bits(value, 5, 5)
        dirty = self.get_bits(value, 6, 6)
        page_size = self.get_bits(value, 7, 7)
        physical_addr = self.get_bits(value, 51, 12) << 12

        flags = []

        if present == 1:
            flags.append("P") # Present
        if rw == 1:
            flags.append("RW") # Read-write
        if us == 1:
            flags.append("S") # Supervisor
        if pwt == 1:
            flags.append("PWT") # Page-level write-through bit. This bit controls whether the write-through caching policy is enabled (1) or disabled (0) for the corresponding page table
        if pcd == 1:
            flags.append("PCD") #  Page-level cache disable bit.
        if accessed == 1:
            flags.append("A") # Has it been accessed?
        if dirty == 1:
            flags.append("D") # has it been written to?
        if page_size == 1:
            flags.append("PS") # page size. 4 kb or 2 mb?

        flags_str = "[" + " ".join(flags) + "]"

        return (flags_str, physical_addr)


    def unmarshall_PT_entry(self, value):
        present = self.get_bits(value, 0, 0)
        rw = self.get_bits(value, 1, 1)
        us = self.get_bits(value, 2, 2)
        pwt = self.get_bits(value, 3, 3)
        pcd = self.get_bits(value, 4, 4)
        accessed = self.get_bits(value, 5, 5)
        dirty = self.get_bits(value, 6, 6)
        page_size = self.get_bits(value, 7, 7)
        is_global = self.get_bits(value, 8, 8)
        physical_addr = self.get_bits(value, 51, 12) << 12
        nx = self.get_bits(value, 63, 63)
        
        flags = []

        if present == 1:
            flags.append("P") # Present
        if rw == 1:
            flags.append("RW") # Read-write
        if us == 1:
            flags.append("S") # Supervisor
        if pwt == 1:
            flags.append("PWT") # Page-level write-through bit. This bit controls whether the write-through caching policy is enabled (1) or disabled (0) for the corresponding page table
        if pcd == 1:
            flags.append("PCD") #  Page-level cache disable bit.
        if accessed == 1:
            flags.append("A") # Has it been accessed?
        if dirty == 1:
            flags.append("D") # has it been written to?
        if page_size == 1:
            flags.append("PS") # page size. 4 kb or 2 mb?
        if is_global == 1:
            flags.append("G") # whether or not the page should be cleared from TLB on a task switch
        if nx == 1:
            flags.append("NX") # non-execute

        flags_str = "[" + " ".join(flags) + "]"

        return (flags_str, physical_addr)




    def get_bits(self, addr, start_bit, end_bit):
        zeroed_left = addr & ((1 << start_bit+1)-1)
        return zeroed_left >> end_bit


    def print_usage_error(self):
        print("Incorrect usage of pte. Use \"pte <addr> [<cr3>] Examples of usage:")
        print("pte 0x55f5a000")
        print("pte 0x55f5a000 0x187f6000")


Pte()
