# Memory tracker for fortigate analysis
The plugin will help track malloc and frees based on user's breakpoint. It requires user's to place breakpoints on all the malloc and free and then run the tracking commands to place the necessary information in the plugin.

## Track malloc
Require two breakpoints: 1 on the malloc and the 1 after malloc is executed\
b = gdb.Breakpoint("*0x164E6DE", gdb.BP_HARDWARE_BREAKPOINT) # To track malloc_block call\
b.commands = 'silent\ntrack_memory malloc_size\ncontinue\n'\
\
b = gdb.Breakpoint("*0x164E6E3", gdb.BP_HARDWARE_BREAKPOINT) # To track malloc_block return\
b.commands = 'silent\ntrack_memory malloc_address\ncontinue\n'\

## Track free
Require one breakpoints: 1 on the free instruction\
b = gdb.Breakpoint("*0x43D090") # track je_free\
b.commands = 'silent\ntrack_memory free\ncontinue\n'\

# Usage

## Valid commands
- raw_summary -> print raw data
- summary -> print data in nice formatting
- process_allocation_order -> trace overflow heap and 0x70 structure for CVE-2022-42475
- process_free -> update malloc which operation frees the heap
- save -> save into a pickled file for future analysis
- load -> load pickled file
- find_free <memory> -> list down free operations that operate on memory address
- find_memory_operation <memory> -> list down operations that operate within the memory range
- list_operations -> list memory operations from range to range 
- list_last_operation -> print the last memory operation
- list_bin_operations <size> -> print out only memory operation with the specified bin size

## Tracking commands
- track_memory malloc_size
- track_memory malloc_address
- track_memory free


## Pre-requisites
Assumes usage of ret-sync (requires patching to work properly in gdb)
