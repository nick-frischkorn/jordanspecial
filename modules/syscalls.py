def generate_syscall_stubs(file_name, virtual_alloc, write_vm, virtual_protect, create_thread, create_file, create_section, map_view, unmap_view, close_handle):

    with open("templates/syswhispers/sys.c", "r") as c_stub:
        stub = c_stub.read()
        stub = stub.replace("NtAllocateVirtualMemory", virtual_alloc)
        stub = stub.replace("NtWriteVirtualMemory", write_vm)
        stub = stub.replace("NtProtectVirtualMemory", virtual_protect)
        stub = stub.replace("NtCreateThreadEx", create_thread)
        stub = stub.replace("NtCreateFile", create_file)
        stub = stub.replace("NtCreateSection", create_section)
        stub = stub.replace("NtMapViewOfSection", map_view)
        stub = stub.replace("NtUnmapViewOfSection", unmap_view)
        stub = stub.replace("NtClose", close_handle)
        stub = stub.replace("REPLACE_WITH_SYSCALL_FILE_NAME", file_name)


    with open("output/" + file_name + ".c", "w") as c_out:
        c_out.write(stub)

    c_stub.close()
    c_out.close()

    with open("templates/syswhispers/sys.h", "r") as h_stub:
        header_stub = h_stub.read()
        header_stub = header_stub.replace("NtAllocateVirtualMemory", virtual_alloc)
        header_stub = header_stub.replace("NtWriteVirtualMemory", write_vm)
        header_stub = header_stub.replace("NtProtectVirtualMemory", virtual_protect)
        header_stub = header_stub.replace("NtCreateThreadEx", create_thread)
        header_stub = header_stub.replace("NtCreateFile", create_file)
        header_stub = header_stub.replace("NtCreateSection", create_section)
        header_stub = header_stub.replace("NtMapViewOfSection", map_view)
        header_stub = header_stub.replace("NtUnmapViewOfSection", unmap_view)
        header_stub = header_stub.replace("NtClose", close_handle)

    with open("output/" + file_name + ".h", "w") as h_out:
        h_out.write(header_stub)

    h_stub.close()
    h_out.close()

    print("[+] Generated syscall files (.c & .h) : %s" % file_name)
