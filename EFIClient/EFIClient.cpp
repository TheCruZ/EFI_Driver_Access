// EFIClient.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <iostream>
#include <sstream>
#include "Driver.h"

bool CheckDriverStatus() {
    int icheck = 82;
    NTSTATUS status = 0;

    uintptr_t BaseAddr = Driver::GetBaseAddress(GetCurrentProcessId());
    if (BaseAddr == 0) {
        return false;
    }

    int checked = Driver::read<int>(GetCurrentProcessId(), (uintptr_t)&icheck, &status);
    if (checked != icheck) {
        return false;
    }
    return true;
}


int main()
{
    if (!Driver::initialize() || !CheckDriverStatus()) {
        UNICODE_STRING VariableName = RTL_CONSTANT_STRING(VARIABLE_NAME);
        NtSetSystemEnvironmentValueEx(
            &VariableName,
            &DummyGuid,
            0,
            0,
            ATTRIBUTES);//delete var

        std::cout << "No EFI Driver found\n";
        system("pause");
        exit(1);
        return 1;
    }

    while (true) {
        system("cls");
        std::cout << "Hi Welcome to EFI Client\n";
        std::cout << "What do you want to do?\n";
        std::cout << "1 - Get process base address by PID\n";
        std::cout << "2 - Read process memory by PID\n";
        std::cout << "3 - Exit\n";
        int action;
        std::cin >> action;
        std::cin.clear();
        std::cin.ignore();
        if (action == 3) {
            std::cout << "Exiting Byee!\n";
            return 0;
        }
        int pid = 0;
        if (action == 1 || action == 2) {
            std::cout << "Process ID:\n";
            std::cin >> pid;
            std::cin.clear();
            std::cin.ignore();
        }


        if (action == 1) {
            uintptr_t BaseAddr = Driver::GetBaseAddress(pid);
            std::cout << "Base Address:\n" << std::hex << BaseAddr << "\n";
            system("pause");
        }
        else if (action == 2) {
            std::cout << "Address(Hex):\n";
            uintptr_t addr = 0;
            std::string addrData;
            std::cin >> addrData;
            std::cin.clear();
            std::cin.ignore();
            addr = std::stoull(addrData, nullptr, 16);
            std::cout << "Number of bytes:\n";
            size_t bytes;
            std::cin >> bytes;
            std::cin.clear();
            std::cin.ignore();

            BYTE* buffer = new BYTE[bytes];
            memset(buffer, 0, bytes);
            Driver::read_memory(pid, addr, (uintptr_t)&buffer[0], bytes);

            std::cout << "Readed:\n";
            for (size_t i = 0; i < bytes; i++) {
                printf("%02X ", buffer[i]);
            }
            printf("\n\n");

            delete[] buffer;

            system("pause");
        }
    }
}
