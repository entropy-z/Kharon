// Macro to cast a value to a generic pointer (PVOID)
#define C_PTR( X ) reinterpret_cast<PVOID>( X )

// Macro to cast a value to an unsigned pointer-sized integer (ULONG_PTR)
#define U_PTR( X ) reinterpret_cast<ULONG_PTR>( X )

// Macro to cast a value to an pointer to bytes (PBYTE)
#define B_PTR( X ) reinterpret_cast<PBYTE>( X )

// Macro to place a variable or function in a specific binary section
#define D_SEC( X ) __attribute__( ( section( X ) ) )

// Macro to check if a pointer or value is nullptr
#define IS_NULL( X ) X == nullptr

#define DFR(Module, Function) DECLSPEC_IMPORT decltype( Function ) Module##$##Function;

