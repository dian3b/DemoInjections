#pragma once

#include <Windows.h>
#include <tchar.h>
#include <vector>
#include <TlHelp32.h>
#include <winternl.h>
#include <iostream>

// 函数声明放在最前面

//LPTHREAD_START_ROUTINE get_load_library_addr();
typedef NTSTATUS(WINAPI* PFN_RtlCreateUserThread)(
    HANDLE ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended,
    ULONG StackZeroBits,
    PULONG StackReserved,
    PULONG StackCommit,
    LPVOID StartAddress,
    LPVOID StartParameter,
    HANDLE* ThreadHandle,
    LPVOID ClientId
    );

using LoadLibraryFunc = DWORD(WINAPI*)(LPVOID);

bool write_to_remote_process_memory(HANDLE h_process, LPVOID remote_mem, const char* data, SIZE_T size) {
    return WriteProcessMemory(h_process, remote_mem, data, size, nullptr);
}

bool get_all_threads_of_process(DWORD process_id, std::vector<HANDLE>& thread_handles) {
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot_handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    THREADENTRY32 thread_entry;
    thread_entry.dwSize = sizeof(THREADENTRY32);
    bool found_threads = false;
    if (Thread32First(snapshot_handle, &thread_entry)) {
        do {
            if (thread_entry.th32OwnerProcessID == process_id) {
                HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_entry.th32ThreadID);
                if (thread_handle) {
                    thread_handles.push_back(thread_handle);
                    found_threads = true;
                }
            }
        } while (Thread32Next(snapshot_handle, &thread_entry));
    }
    CloseHandle(snapshot_handle);
    return found_threads;
}


LPTHREAD_START_ROUTINE get_load_library_address() {
    HMODULE kernel32_mod = GetModuleHandleA("kernel32.dll");
    if (!kernel32_mod) {
        return nullptr;
    }
    auto loadLibraryFunc = reinterpret_cast<LoadLibraryFunc>(GetProcAddress(kernel32_mod, "LoadLibraryA"));
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryFunc);
}
namespace APCTargetedInjection {
    bool inject_dll_by_apc(DWORD process_id, const char* dll_path) {
        HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
        if (!process_handle) {
            std::cout << "FAIL_OPEN_PROCESS" << std::endl;
            return false;
        }
        SIZE_T buffer_length = strlen(dll_path) + 1;
        LPVOID remote_memory = VirtualAllocEx(process_handle, nullptr, buffer_length, MEM_COMMIT, PAGE_READWRITE);
        if (!remote_memory) {
            std::cout << "FAIL_ALLOC_MEM" << std::endl;
            CloseHandle(process_handle);
            return false;
        }
        if (!write_to_remote_process_memory(process_handle, remote_memory, dll_path, buffer_length)) {
            std::cout << "FAIL_WRITE_MEM" << std::endl;
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return false;
        }
        HMODULE kernel32_module_base = GetModuleHandleA("kernel32.dll");
        if (!kernel32_module_base) {
            std::cout << "FAIL_GET_KERNEL32_MODULE" << std::endl;
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return false;
        }
        LPTHREAD_START_ROUTINE load_library_addr = get_load_library_address();
        if (!load_library_addr) {
            std::cout << "FAIL_GET_ADDR" << std::endl;
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return false;
        }
        PAPCFUNC apc_function_pointer = (PAPCFUNC)load_library_addr;
        std::vector<HANDLE> thread_handles;
        if (!get_all_threads_of_process(process_id, thread_handles)) {
            std::cout << "FAIL_GET_THREADS" << std::endl;
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return false;
        }
        for (const auto& thread_handle : thread_handles) {
            if (QueueUserAPC(apc_function_pointer, thread_handle, (ULONG_PTR)remote_memory)) {
                std::cout << "APC queued for thread." << std::endl;
            }
            else {
                std::cout << "FAIL_QUEUE_APC" << std::endl;
            }
            CloseHandle(thread_handle);
        }
        VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        return true;
    }
}

namespace RemoteThreadInjection {
    bool inject_dll_to_process(DWORD process_id, const char* dll_path) {
        HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
        if (!process_handle) {
            std::cout << "FAIL_OPEN_PROCESS" << std::endl;
            return false;
        }
        LPVOID remote_memory = VirtualAllocEx(process_handle, nullptr, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
        if (!remote_memory) {
            std::cout << "FAIL_ALLOC_MEM" << std::endl;
            CloseHandle(process_handle);
            return false;
        }
        if (!write_to_remote_process_memory(process_handle, remote_memory, dll_path, strlen(dll_path) + 1)) {
            std::cout << "FAIL_WRITE_MEM" << std::endl;
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return false;
        }
        LPTHREAD_START_ROUTINE load_library_addr = get_load_library_address();
        if (!load_library_addr) {
            std::cout << "FAIL_GET_ADDR" << std::endl;
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return false;
        }
        HANDLE h_thread = CreateRemoteThread(process_handle, nullptr, 0, load_library_addr, remote_memory, 0, nullptr);
        if (!h_thread) {
            std::cout << "FAIL_CREATE_THREAD" << std::endl;
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return false;
        }
        WaitForSingleObject(h_thread, INFINITE);
        VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
        CloseHandle(h_thread);
        CloseHandle(process_handle);
        return true;
    }
}

namespace RtlCreateThreadInjection {
    bool inject_dll_by_rtl_create_user_thread(DWORD process_id, const char* dll_path) {
        HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
        if (!process_handle) {
            std::cout << "FAIL_OPEN_PROCESS" << std::endl;
            return false;
        }
        HMODULE ntdll_module = GetModuleHandleA("ntdll.dll");
        if (!ntdll_module) {
            std::cout << "FAIL_GET_NTDLL_MODULE" << std::endl;
            CloseHandle(process_handle);
            return false;
        }
        PFN_RtlCreateUserThread rtl_create_user_thread_ptr = reinterpret_cast<PFN_RtlCreateUserThread>(GetProcAddress(ntdll_module, "RtlCreateUserThread"));
        if (!rtl_create_user_thread_ptr) {
            std::cout << "FAIL_GET_RtlCreateUserThread_FUNCTION" << std::endl;
            CloseHandle(process_handle);
            return false;
        }
        LPTHREAD_START_ROUTINE load_library_addr = get_load_library_address();
        if (!load_library_addr) {
            std::cout << "FAIL_GET_ADDR" << std::endl;
            CloseHandle(process_handle);
            return false;
        }
        HANDLE h_thread;
        NTSTATUS status = rtl_create_user_thread_ptr(process_handle, nullptr, FALSE, 0, nullptr, nullptr, nullptr, load_library_addr, reinterpret_cast<LPVOID*>(&h_thread), nullptr);
        if (status != 0) {
            std::cout << "FAIL_CREATE_THREAD_WITH_RtlCreateUserThread" << std::endl;
            CloseHandle(process_handle);
            return false;
        }
        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread);
        CloseHandle(process_handle);
        return true;
    }
}

namespace WindowsHookInjection {
    bool inject_dll_by_set_windows_hook_ex(DWORD process_id, const char* dll_path, DWORD target_thread_id) {
        HMODULE h_dll = LoadLibraryA(dll_path);
        if (!h_dll) {
            std::cout << "FAIL_LOAD_DLL" << std::endl;
            return false;
        }
        HOOKPROC hook_proc = (HOOKPROC)GetProcAddress(h_dll, "HookProc");
        if (!hook_proc) {
            std::cout << "FAIL_GET_HOOK_PROC" << std::endl;
            FreeLibrary(h_dll);
            return false;
        }
        HHOOK hook_handle = SetWindowsHookEx(WH_KEYBOARD, hook_proc, h_dll, target_thread_id);
        if (!hook_handle) {
            std::cout << "FAIL_SET_HOOK" << std::endl;
            FreeLibrary(h_dll);
            return false;
        }
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        UnhookWindowsHookEx(hook_handle);
        FreeLibrary(h_dll);
        return true;
    }
}