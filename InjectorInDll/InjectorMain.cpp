//#include "DemoInjector.h"

#include "DemoInjections.h"
#include "RegistryInjection.h"



#pragma once

int main(int argc, char* argv[]) {
    std::string method;
    DWORD target_process_id;
    std::string dll_path;
    DWORD target_thread_id = 0;

    if (argc == 4 || argc == 5) {
        method = argv[1];
        target_process_id = atoi(argv[2]);
        dll_path = argv[3];
        if (argc == 5) {
            target_thread_id = atoi(argv[4]);
        }
    }
    else {
        std::cout << "Enter injection method (remote_thread/apc/setwindowshookex/registry/rtlcreatethread): ";
        std::cin >> method;
        std::cout << "Enter target process ID: ";
        std::cin >> target_process_id;
        std::cout << "Enter DLL path: ";
        std::cin >> dll_path;
        if (method == "setwindowshookex") {
            std::cout << "Enter target thread ID (optional, enter 0 for all threads): ";
            std::cin >> target_thread_id;
        }
    }
    bool injection_result = false;

    if (method == "remote_thread") {
        injection_result = RemoteThreadInjection::inject_dll_to_process(target_process_id, dll_path.c_str());
        if (injection_result == true) {
            MessageBox(nullptr, nullptr, _T("INJECTION_SUCCESS"), 0);
        }
        else {
            std::cout << "FAIL_INJECTION_BY_REMOTE_THREAD" << std::endl;
        }
    }
    if (method == "apc") {
        injection_result = APCTargetedInjection::inject_dll_by_apc(target_process_id, dll_path.c_str());
        if (injection_result == true) {
            MessageBox(nullptr, nullptr, _T("INJECTION_SUCCESS_BY_APC"), 0);
        }
        else {
            std::cout << "FAIL_INJECTION_BY_APC" << std::endl;
        }
    }
    else if (method == "setwindowshookex") {

        injection_result = WindowsHookInjection::inject_dll_by_set_windows_hook_ex(target_process_id, dll_path.c_str(), target_thread_id);
        if (injection_result == true) {
            MessageBox(nullptr, nullptr, _T("INJECTION_SUCCESS_BY_SETWINDOWHOOKEX"), 0);
        }
        else {
            std::cout << "FAIL_INJECTION_BY_SETWINDOWHOOKEX" << std::endl;
        }
    }
    else if (method == "registry") {
        injection_result = RegistryInjection::inject_dll_by_registry(dll_path.c_str());
        if (injection_result == true) {
            MessageBox(nullptr, nullptr, _T("INJECTION_SUCCESS_BY_REGISTRY"), 0);
        }
        else {
            std::cout << "FAIL_INJECTION_BY_REGISTRY" << std::endl;
        }
    }
     else if (method == "rtlcreatethread") {
        injection_result = RtlCreateThreadInjection::inject_dll_by_rtl_create_user_thread(target_process_id, dll_path.c_str());
        if (injection_result == true) {
            MessageBox(nullptr, nullptr, _T("INJECTION_SUCCESS_BY_RtlCreateUserThread"), 0);
        }
        else {
            std::cout << "FAIL_INJECTION_BY_RtlCreateUserThread" << std::endl;
        }
    }
    else {
        std::cout << "INVALID_INJECTION_METHOD" << std::endl;
    }

    return 0;
}