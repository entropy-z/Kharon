#ifndef BEACON_HPP
#define BEACON_HPP

#include <Windows.h>

/// @struct Data
/// @brief Represents a managed data buffer with additional metadata.
///
/// This structure is used to manage a data buffer, including the original buffer,
/// the current read/write position, the total size, and the remaining available space.
struct Data {
    /// @brief Pointer to the original buffer.
    /// 
    /// Stores the address of the original buffer to ensure proper deallocation
    /// of dynamically allocated memory.
    PCHAR Original;

    /// @brief Pointer to the current position in the buffer.
    /// Indicates the current read or write position within the buffer.
    PCHAR Buffer;

    /// @brief Remaining length of the buffer.
    /// 
    /// Represents the amount of space still available for reading or writing.
    INT Length;

    /// @brief Total size of the buffer.
    /// 
    /// Represents the total size of the managed buffer in bytes.
    INT Size;
};

/// @struct Format
/// @brief Represents a managed data buffer with metadata for tracking its state.
/// This structure is designed to manage a buffer, keeping track of the original 
/// allocation, current position, remaining space, and total size.
struct Format {
    /// @brief Pointer to the original buffer.
    /// Holds the address of the original buffer allocation, allowing proper
    /// deallocation of dynamically allocated memory.
    PCHAR Original;

    /// @brief Pointer to the current position in the buffer.
    /// Tracks the current read or write position within the buffer.
    PCHAR Buffer;

    /// @brief Remaining length in the buffer.
    /// Indicates how much space is left for additional data.
    INT Length;

    /// @brief Total size of the buffer.
    /// Specifies the total size of the buffer in bytes.
    INT Size;
};

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

EXTERN_C {
    DECLSPEC_IMPORT VOID  BeaconPrintf         (INT Type, const char* Fmt, ...);
    DECLSPEC_IMPORT VOID  BeaconOutput         (INT Type, PCHAR Data, INT Len);
    DECLSPEC_IMPORT BOOL  BeaconUseToken       (HANDLE Token);
    DECLSPEC_IMPORT VOID  BeaconRevertToken    ();
    DECLSPEC_IMPORT BOOL  BeaconIsAdmin        ();

    DECLSPEC_IMPORT VOID  BeaconDataParse      (Data* Parser, PCHAR Buffer, INT Size);
    DECLSPEC_IMPORT INT   BeaconDataInt        (Data* Parser);
    DECLSPEC_IMPORT SHORT BeaconDataShort      (Data* Parser);
    DECLSPEC_IMPORT INT   BeaconDataLength     (Data* Parser);
    DECLSPEC_IMPORT PCHAR BeaconDataExtract    (Data* Parser, PINT Size);

    DECLSPEC_IMPORT VOID  BeaconFormatAlloc    (Format* Format, INT Maxsz);
    DECLSPEC_IMPORT VOID  BeaconFormatReset    (Format* Format);
    DECLSPEC_IMPORT VOID  BeaconFormatFree     (Format* Format);
    DECLSPEC_IMPORT VOID  BeaconFormatAppend   (Format* Format, PCHAR Text, INT Len);
    DECLSPEC_IMPORT VOID  BeaconFormatPrintf   (Format* Format, PCHAR Fmt, ...);
    DECLSPEC_IMPORT PCHAR BeaconFormatToString (Format* Format, PINT Size);
    DECLSPEC_IMPORT VOID  BeaconFormatInt      (Format* Format, INT Value);
}

namespace Beacon {
    /* Wrapper for the native BeaconPrintf function with variadic arguments.
    *
    * This function simplifies and encapsulates the call to `BeaconPrintf`,
    * ensuring proper handling of variadic arguments for formatted output.
    *
    * @param Type The type of message (e.g., error, debug, info).
    * @param Fmt Format string for the message (similar to printf-style).
    * @param ... Variadic arguments for the format string.
    */
    static VOID Printf(INT Type, const char* Fmt, ...) {
        //
        // Initialize variadic argument list
        //
        va_list Args;
        va_start( Args, Fmt );
        
        //
        // Print Beacon
        //
        BeaconPrintf( Type, Fmt, Args );
        
        //
        // End va
        //
        va_end( Args );
    };
}

#endif // BEACON_HPP