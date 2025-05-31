#include <Kharon.h>

auto Transport::Send(
    _In_      PVOID   Data,
    _In_      UINT64  Size,
    _Out_opt_ PVOID  *RecvData,
    _Out_opt_ UINT64 *RecvSize
) -> BOOL {
#ifdef PROFILE_WEB
    return Self->Tsp->WebSend(
        Data, Size, RecvDatam RecvSize
    );
#elif  PROBILE_SMB
    return Self->Tsp->SmbSend(
        Data, Size, RecvDatam RecvSize
    );
#endif
}