#include <windows.h>

#include <native.h>

#include <Shellcode.h>
#include <Injection.h>
#include <Encryption.h>

#define DLLEXPORT __declspec(dllexport)

auto EntryLoader( VOID ) -> VOID;
