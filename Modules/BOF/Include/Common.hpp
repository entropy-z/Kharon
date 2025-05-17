#ifndef COMMON_HPP
#define COMMON_HPP

#include <Windows.h>
#include <Macros.hpp>
#include <Msvcrt.hpp>
#include <Beacon.hpp>
#include <Dnsapi.hpp>
#include <Kernel32.hpp>
#include <Iphlpapi.hpp>


#define BUFFER_SIZE  8192
D_SEC(".data") CHAR* Output  = 0;
D_SEC(".data") WORD  CurrentBufferSize = 0; 

namespace Mem {
    /**
     * @brief Copies data from a source to a destination in memory.
     * 
     * The type of the destination and source pointer (must be a valid pointer).
     * @param Dest Pointer to the destination location.
     * @param Src Pointer to the source data.
     * @param Size Size in bytes to be copied.
     * @return T Returns the destination pointer.
    */
    template< typename T >
    static T Copy(T Dest, const T Src, SIZE_T Size) {
        return static_cast<T>( __builtin_memcpy( Dest, Src, Size ) );
    }

    /**
     * @brief Defines a specific value for a memory block.
     * 
     * The type of the destination pointer (must be a valid pointer).
     * @param Dst Pointer to the destination memory block.
     * @param Value Value to be set in each byte of the memory block.
     * @param Size Size in bytes of the memory block.
     * @return T Returns the destination pointer.
     */
    template< typename T >
    static VOID Set(T Dst, INT Value, SIZE_T Size) {
        __stosb( reinterpret_cast<unsigned char*>( Dst ), Value, Size );
    }

    /**
     * @brief Allocates a block of memory from the heap.
     * 
     * @tparam T The type of the pointer to be allocated.
     * @param Size The size of the memory block to allocate (in bytes).
     * @return T* Pointer to the allocated memory block, or NULL if allocation fails.
     */
    template< typename T >
    static T* Alloc(SIZE_T Size) {
        return static_cast<T*>( HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, Size ) );
    }

    /**
     * @brief Frees a block of memory previously allocated with `Alloc`.
     * 
     * @param Ptr Pointer to the memory block to be freed.
     * @return BOOL Returns TRUE if the memory was successfully freed, FALSE otherwise.
     */
    static BOOL Free(PVOID Ptr) {
        return HeapFree( GetProcessHeap(), 0x00, Ptr );
    } 
};

/**
 * @brief Initializes the output buffer.
 * 
 * Allocates memory for the global output buffer and initializes `CurrentBufferSize` to 0.
 * 
 * @return INT Returns EXIT_SUCCESS on success.
 */
INT Start() {
    Output = Mem::Alloc<char>( BUFFER_SIZE );
    CurrentBufferSize = 0;
    return EXIT_SUCCESS; 
}

/**
 * @brief Sends the current contents of the output buffer to the beacon output.
 * 
 * @param Done If TRUE, the buffer is freed after sending its contents.
 */
VOID PrintOutput(BOOL Done) {
    if ( CurrentBufferSize > 0 ) {
        BeaconOutput( 0, Output, CurrentBufferSize );
        CurrentBufferSize = 0;
        Mem::Set( Output, 0, BUFFER_SIZE );
    }

    if ( Done ) {
        Mem::Free( Output );
    }
}

/**
 * @brief Writes a formatted string to the output buffer.
 * 
 * If the buffer is full, it automatically flushes the current contents before continuing.
 * 
 * @param Format The format string (similar to printf).
 * @param ... Arguments matching the placeholders in the format string.
 */
VOID Printf(const char* Format, ...) {
    va_list Args;
    va_start( Args, Format );

    while ( TRUE ) {
        INT Written = vsnprintf( Output + CurrentBufferSize, BUFFER_SIZE - CurrentBufferSize, Format, Args );

        if ( Written < 0 ) { 
            va_end( Args ); 
            return;
        }

        if ( ( SIZE_T )Written + CurrentBufferSize >= BUFFER_SIZE ) {
            PrintOutput( FALSE );
        } else {
            CurrentBufferSize += Written;
            break;
        }
    }

    va_end(Args);
}

/**
 * @brief Converts a UTF-16 string (wchar_t*) to a UTF-8 string (char*).
 * 
 * @param Input Pointer to the wide string (UTF-16) to be converted.
 * @return PCHAR Pointer to the newly allocated UTF-8 string, or NULL on failure.
 *         The caller is responsible for freeing the returned string.
 */
PCHAR WideToUtf8(const wchar_t* Input) {
    if ( IS_NULL( Input ) ) return nullptr;

    //
    // 
    //
    INT Size = WideCharToMultiByte(
        CP_UTF8,
        0,
        Input,
        -1,
        nullptr,
        0,
        nullptr,
        nullptr
    );

    if ( Size <= 0 ) return nullptr;

    PCHAR Str = static_cast<PCHAR>( Mem::Alloc<char>( Size ) );
    if ( IS_NULL( Str ) ) return nullptr;

    //
    // 
    //
    INT Result = WideCharToMultiByte(
        CP_UTF8,
        0,
        Input,
        -1,
        Str,
        Size,
        nullptr,
        nullptr
    );

    if (Result <= 0) return nullptr;

    return Str;
}

#endif