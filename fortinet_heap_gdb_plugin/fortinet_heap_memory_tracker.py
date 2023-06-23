import gdb
import pickle

class MemoryTracker(gdb.Command):
    def __init__(self):
        super(MemoryTracker, self).__init__("track_memory", gdb.COMMAND_USER)
        self.allocations_tracker = [] # Tuple (number, operation, memory, stacktrace)
    
    def complete(self, text, word):
        valid_user_commands = ['raw_summary','summary','process_allocation_order','process_free', 'save', 'load', 'find_free','find_memory_operation','list_operations','list_last_operation', 'list_bin_operations']

        if (text == ''):
            return valid_user_commands
        else:
            to_return_commands = []
            for commands in valid_user_commands:
                if commands.startswith(text):
                    to_return_commands.append(commands)
            
            return to_return_commands

    def invoke(self, arg, from_tty):
        if arg == "malloc_size":
            raw_result = gdb.execute('printf "%d",$rdi', to_string=True)
            stack = gdb.execute('bbt', to_string=True)
            self.allocations_tracker.append((self.get_operation_number(), "malloc %s" % (raw_result), "Pending", stack))
        elif arg == "malloc_address":
            raw_result = gdb.execute('printf "%p",$rax', to_string=True)
            target_entry = self.update_memory_in_allocation_tracker(raw_result)
        elif arg == "free":
            raw_result = gdb.execute('printf "%p",$rdi', to_string=True)
            stack = gdb.execute('bt', to_string=True)
            self.allocations_tracker.append((self.get_operation_number(), "free", raw_result, stack))
            self.update_free(raw_result)
        elif arg == "raw_summary":
            print(self.allocations_tracker)
        elif arg == "summary":
            self.summary()
        elif arg == "process_allocation_order": 
            self.process_allocation_order()
        elif arg == "process_free":
            self.process_free()
        elif arg == "update_free":
            memory = arg.split(' ')[1]
            self.update_free(memory)
        elif arg.startswith("find_free"):
            memory = arg.split(' ')[1]
            self.find_free(memory)
        elif arg.startswith('find_memory_operation'):
            memory = arg.split(' ')[1]
            self.find_memory_operation(memory)
        elif arg.startswith('list_operations'):
            self.list_operations(arg)
        elif arg.startswith('list_last_operation'):
            self.list_last_operation()
        elif arg.startswith('list_bin_operations'):
            self.list_bin_operations(arg)
        elif arg == "save":
            with open('/tmp/memorytracker.pickle', 'wb') as fd:
                pickle.dump(self.allocations_tracker, fd, protocol=pickle.HIGHEST_PROTOCOL)
        elif arg == "load":
            with open('/tmp/memorytracker.pickle', 'rb') as fd:
                self.allocations_tracker = pickle.load(fd)
                self.process_free()


    def summary(self):
        for i in range(len(self.allocations_tracker)):
            temp_tuple = self.allocations_tracker[i]
            print("%s %s %s %s" % (temp_tuple[0], temp_tuple[1], temp_tuple[2], temp_tuple[3].replace('\n',' ')))

    def process_allocation_order(self):
        allocations_of_interest = {}
        counter = 1
        for i in range(len(self.allocations_tracker)):
            temp_tuple = self.allocations_tracker[i]
            if "structure0x70_alloc_1" in temp_tuple[3]:
                allocations_of_interest["%s - %s" % (temp_tuple[2],temp_tuple[0])] = (temp_tuple[0], "0x70 structure alloc %d" % counter, temp_tuple[2])
                # print("%s %s <- %s" % (temp_tuple[1], temp_tuple[2], "0x70 structure alloc %d" % counter))
            if  "read_post_data_callback" in temp_tuple[3]:
                allocations_of_interest["%s - %s" % (temp_tuple[2],temp_tuple[0])] = (temp_tuple[0], "heap alloc %d"% counter, temp_tuple[2])
                # print("%s %s <- %s" % (temp_tuple[1], temp_tuple[2], "heap alloc %d" % counter))
                counter += 1

        # Sorting the allocations based on memory address
        for i in sorted(allocations_of_interest):
            print("%s %s" % (i, allocations_of_interest[i]))
    
    def update_free(self, memory):
        if len(self.allocations_tracker) <= 1:
            return

        current_tuple = self.allocations_tracker[len(self.allocations_tracker)-1]

        for i in range(len(self.allocations_tracker)-2, -1, -1):
            temp_tuple = self.allocations_tracker[i]
            if temp_tuple[2] == memory:
                if temp_tuple[1].startswith("free"):
                    return
                elif temp_tuple[1].startswith("malloc"):
                    # Update and return
                    size = temp_tuple[1].split(' ')[1]
                    # Update free
                    overwrite_tuple = (current_tuple[0], "free %s" % size, memory, current_tuple[3])
                    self.allocations_tracker[len(self.allocations_tracker)-1] = overwrite_tuple
                    # Update malloc
                    overwrite_tuple = (temp_tuple[0], temp_tuple[1] + " freed in %d" % current_tuple[0], memory, temp_tuple[3])
                    self.allocations_tracker[i] = overwrite_tuple
                    return


    def process_free(self):
        cache_table = {}
        for i in range(len(self.allocations_tracker)):
            temp_tuple = self.allocations_tracker[i]
            if temp_tuple[1].startswith('free'):
                for j in range(i-1,-1,-1):
                    find_tuple = self.allocations_tracker[j]
                    if find_tuple[1].startswith('malloc') and find_tuple[2] == temp_tuple[2]:
                        size = find_tuple[1].split(' ')[1]
                        malloc_operation_number = find_tuple[0]
                        overwrite_tuple = (temp_tuple[0], "free %s malloc in %d" % (size,malloc_operation_number), temp_tuple[2], temp_tuple[3])
                        self.allocations_tracker[i] = overwrite_tuple
                        break
                # Update stacktrace
                bt = temp_tuple[3].split("\n")
                bt = [l.split() for l in bt]
                bt = bt[:-1]  # remove [] at the end
                for trace in bt:
                    
                    raddr = trace[1]
                    symbol = trace[3]   

                    if symbol == '??':
                        if raddr not in cache_table:
                        
                            resolved_symbol = gdb.execute("rln %s" % raddr, to_string=True)
                            if '+' in resolved_symbol:
                                resolved_symbol = resolved_symbol.split('+')[0]
                            
                            if resolved_symbol.split(':')[1] == " ":
                                resolved_symbol = "??"
                            else:
                                resolved_symbol = resolved_symbol.split(':')[1].strip()

                            trace[3] = resolved_symbol
                            cache_table[raddr] = resolved_symbol

                        else:
                            trace[3] = cache_table[raddr]
                    
                
                bt = "\n".join([" ".join(trace) for trace in bt])
                
                overwrite_tuple = (temp_tuple[0], temp_tuple[1], temp_tuple[2], bt)
                self.allocations_tracker[i] = overwrite_tuple
                
            
                        
                        

    def list_operations(self, arg):
        if len(arg.split(' ')) == 1:
            lower = 1
            upper = len(self.allocations_tracker)
        else:
            lower = arg.split(' ')[1]
            upper = arg.split(' ')[2]


        for i in range(int(lower)-1,int(upper)):
            temp_tuple = self.allocations_tracker[i]
            print("%s %s %s" % (temp_tuple[0], temp_tuple[1], temp_tuple[2]))

    def list_last_operation(self):
        temp_tuple = self.allocations_tracker[len(self.allocations_tracker)-1]
        if "1000" in temp_tuple[1] or "free" in temp_tuple[1] or 1:
            print("%s %s %s" % (temp_tuple[0], temp_tuple[1], temp_tuple[2]))

    def list_bin_operations(self, args):
        bin_size = args.split(" ")[1]
        for i in range(len(self.allocations_tracker)):
            temp_tuple = self.allocations_tracker[i]
            try:
                tuple_size = temp_tuple[1].split(' ')[1]
                if tuple_size == bin_size:
                    print("%s %s %s" % (temp_tuple[0], temp_tuple[1], temp_tuple[2]))
            except:
                continue

        if '--func-call' in args:
            breakpoint_addresses = {}
            for i in range(len(self.allocations_tracker)):
                temp_tuple = self.allocations_tracker[i]
                try:
                    tuple_size = temp_tuple[1].split(' ')[1]
                    if tuple_size == bin_size:
                        breakpoint_addr = temp_tuple[3].split('\n')[1].split(' ')[1]
                            
                        if breakpoint_addr not in breakpoint_addresses:
                            breakpoint_addresses[breakpoint_addr] = 1
                        else:
                            breakpoint_addresses[breakpoint_addr] += 1
                except:
                    continue
            
            print(breakpoint_addresses.keys())


    def find_free(self, memory):
        for i in range(len(self.allocations_tracker)):
            temp_tuple = self.allocations_tracker[i]
            if "free" == temp_tuple[1] and memory == temp_tuple[2]:
                print("%s %s %s \n%s\n" % (temp_tuple[0], temp_tuple[1], temp_tuple[2], '\n'.join(temp_tuple[3].split('\n')[1:])))

    def find_memory_operation(self, memory):
        for i in range(len(self.allocations_tracker)):
            temp_tuple = self.allocations_tracker[i]
            if temp_tuple[1].startswith("malloc"):
                size = int(temp_tuple[1].split(' ')[1])
                lower_range = int(temp_tuple[2],16)
                upper_range = int(temp_tuple[2],16) + size
                if int(memory,16) < upper_range and int(memory, 16) >= lower_range:
                    print("%s %s %s\n%s\n" % (temp_tuple[0], temp_tuple[1], temp_tuple[2], '\n'.join(temp_tuple[3].split('\n')[0:])))
            elif temp_tuple[1].startswith("free"):
                if len(temp_tuple[1].split(' ')) == 1:
                    # No range - check direct
                    if memory == temp_tuple[2]:
                        print("%s %s %s\n%s\n" % (temp_tuple[0], temp_tuple[1], temp_tuple[2], '\n'.join(temp_tuple[3].split('\n')[0:])))
                else:
                    size = int(temp_tuple[1].split(' ')[1])
                    lower_range = int(temp_tuple[2],16)
                    upper_range = int(temp_tuple[2],16) + size
                    if int(memory,16) < upper_range and int(memory, 16) >= lower_range:
                        print("%s %s %s\n%s\n" % (temp_tuple[0], temp_tuple[1], temp_tuple[2], '\n'.join(temp_tuple[3].split('\n')[0:])))



    def get_operation_number(self):
        return len(self.allocations_tracker) + 1

    def update_memory_in_allocation_tracker(self, allocated_memory):
        
        temp_tuple = self.allocations_tracker[len(self.allocations_tracker)-1]
        if temp_tuple[2] == "Pending":
            if "read_post_data_callback" in temp_tuple[3]:
                overwrite_tuple = (temp_tuple[0], "%s -> heap" % temp_tuple[1], allocated_memory, temp_tuple[3])
            elif "structure0x70_alloc_1" in temp_tuple[3]:
                overwrite_tuple = (temp_tuple[0], "%s -> 0x70struct" % temp_tuple[1], allocated_memory, temp_tuple[3])
            elif "install_ssl" in temp_tuple[3]:
                overwrite_tuple = (temp_tuple[0], "%s -> ssl_callback" % temp_tuple[1], allocated_memory, temp_tuple[3])
            else:
                overwrite_tuple = (temp_tuple[0], temp_tuple[1], allocated_memory, temp_tuple[3])

            self.allocations_tracker[len(self.allocations_tracker)-1] = overwrite_tuple
        else:
            print("Error updating memory for malloc")

        

MemoryTracker()
