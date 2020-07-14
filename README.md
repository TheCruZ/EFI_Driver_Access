# EFI Driver Access
Efi Driver Access is a simply project to load a driver during system boot with the idea to give the user kernel access for read/write memory without restrictions

## CRZEFI
CRZEFI is the EFI Driver itself and is based on other publications like https://github.com/SamuelTulach/efi-memory

The difference of this one basically is that is prepared to call some windows kernel function directly for the user access

## EFIClient
EFIClient is a simply Console example for the usage of EFI Driver

One of the main examples where i use this driver is in: https://www.unknowncheats.me/forum/apex-legends/405983-direct-efi-aimbot-glow-hack.html

## Compilling
To compile EFIClient is easiest as you only need to install Visual Studio, open the project, and compile it

For the CRZEFI is very simple too but you must have a gcc compiler with gnu-efi, the easiest method to have this enviroment is install an ubuntu desktop/server somewhere and run the next commands:

    sudo apt install gnu-efi build-essential
    git clone https://github.com/TheCruZ/EFI_Driver_Access
    cd EFI_Driver_Access
    cd CRZEFI
    make

And it should generate a memory.efi file

## How To Use
You have to put in a USB Driver the edk2 efi shell: https://github.com/tianocore/edk2/releases in the path

    /EFI/Boot/bootx64.efi

and then leave the memory.efi somethere in the USB Driver for example in

    /memory.efi


Now you can bootup with you usb and load the efi file with the "load memory.efi" command (going first to the USB folder that can be FS0, FS1, FS2...) and then come back to your boot menu/bios to run windows normally, you will know that the memory.efi is working because will set blue background while windows system is loading


Have a fun and keep learning!