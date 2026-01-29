#include <general.h>
#include <strsafe.h>

#include <general.h>
#include <strsafe.h>

auto GetUserByToken(
    _In_ HANDLE token_handle
) -> WCHAR* {
    TOKEN_USER*  token_user_ptr = nullptr;
    SID_NAME_USE sid_name       = SidTypeUnknown;
    NTSTATUS     status         = STATUS_SUCCESS;

    WCHAR* user_domain = nullptr;
    WCHAR* domain      = nullptr;
    WCHAR* username    = nullptr;
    ULONG  total_len   = 0;
    ULONG  return_len  = 0;
    ULONG  domain_len  = 0;
    ULONG  username_ln = 0;
    BOOL   success     = FALSE;

    auto cleanup = [&]( void ) -> WCHAR* {
        if ( token_user_ptr ) {
            free( token_user_ptr );
        }

        if ( domain ) {
            free( domain );
        }

        if ( username ) {
            free( username );
        }

        if ( ! success ) {
            if ( user_domain ) {
                free( user_domain );
            }
            
            user_domain = nullptr;
        }

        return user_domain;
    };

    status = NtQueryInformationToken( token_handle, TokenUser, nullptr, 0, &return_len );
    if ( status != STATUS_BUFFER_TOO_SMALL ) {
        return cleanup();
    }

    token_user_ptr = (TOKEN_USER*)malloc( return_len );
    if ( ! token_user_ptr ) {
        return cleanup();
    }

    status = NtQueryInformationToken( token_handle, TokenUser, token_user_ptr, return_len, &return_len );
    if ( ! nt_success( status ) ) {  
        return cleanup();
    }

    LookupAccountSidW(  
        nullptr, token_user_ptr->User.Sid, nullptr,
        &username_ln, nullptr, &domain_len, &sid_name
    );
    if ( GetLastError() != ERROR_INSUFFICIENT_BUFFER ) {
        return cleanup();
    }
    
    total_len = username_ln + domain_len + 2;

    user_domain = (WCHAR*)malloc( total_len * sizeof(WCHAR) );
    if ( ! user_domain ) {
        return cleanup();
    }

    domain   = (WCHAR*)malloc( domain_len * sizeof(WCHAR) );
    username = (WCHAR*)malloc( username_ln * sizeof(WCHAR) );

    if ( ! domain || ! username ) {
        return cleanup();
    }

    success = LookupAccountSidW(
        nullptr, token_user_ptr->User.Sid, username,
        &username_ln, domain, &domain_len, &sid_name
    );
    if ( ! success ) {
        return cleanup();
    }

    _swprintf( user_domain, L"%s\\%s", domain, username );

    return cleanup();
}

extern "C" auto go( char* args, int argc ) -> void {
    datap data_parser = { 0 };

    PVOID  base_sysproc  = nullptr;
    ULONG  return_length = 0;
    NTSTATUS status      = STATUS_SUCCESS;
    BOOL   Isx64         = FALSE;
    WCHAR* user_token    = nullptr;

    HANDLE token_handle   = nullptr;
    HANDLE process_handle = nullptr;

    SYSTEM_PROCESS_INFORMATION* system_proc_info = nullptr; 

    NtQuerySystemInformation( SystemProcessInformation, nullptr, 0, &return_length );

    system_proc_info = (SYSTEM_PROCESS_INFORMATION*)malloc( return_length );
    if ( ! system_proc_info ) {
        return;
    }
    
    status = NtQuerySystemInformation( SystemProcessInformation, system_proc_info, return_length, &return_length );
    if ( ! nt_success( status ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to get system process information, error: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        free( system_proc_info ); 
        return;
    }

    base_sysproc = system_proc_info;

    do {
        process_handle = nullptr;
        token_handle   = nullptr;
        user_token     = nullptr;
        Isx64          = FALSE;

        process_handle = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, HandleToUlong( system_proc_info->UniqueProcessId ) );

        if ( system_proc_info->ImageName.Buffer ) {
            BeaconPkgBytes( (PBYTE)system_proc_info->ImageName.Buffer, system_proc_info->ImageName.Length );
        } else {
            BeaconPkgBytes( (PBYTE)L"[System]", wcslen(L"[System]") * sizeof(WCHAR) );
        }

        BeaconPkgInt32( HandleToUlong( system_proc_info->UniqueProcessId ) );
        BeaconPkgInt32( HandleToUlong( system_proc_info->InheritedFromUniqueProcessId ) );
        BeaconPkgInt32( system_proc_info->SessionId );

        if ( process_handle ) {
            if ( OpenProcessToken( process_handle, TOKEN_QUERY, &token_handle ) && token_handle ) {
                user_token = GetUserByToken( token_handle );
                CloseHandle( token_handle );
            }

            IsWow64Process( process_handle, &Isx64 );
            CloseHandle( process_handle ); 
        }

        if ( ! user_token ) {
            BeaconPkgBytes( (PBYTE)L"N/A", wcslen(L"N/A") * sizeof(WCHAR) );
        } else {
            BeaconPkgBytes( (PBYTE)user_token, wcslen( user_token ) * sizeof(WCHAR) );
            free( user_token );
        }

        BeaconPkgInt32( Isx64 );

        if ( system_proc_info->NextEntryOffset == 0 ) {
            break;
        }

        system_proc_info = (PSYSTEM_PROCESS_INFORMATION)( (UINT_PTR)system_proc_info + system_proc_info->NextEntryOffset );

    } while ( TRUE );

    if ( base_sysproc ) {
        free( base_sysproc );
    }

    return;
}