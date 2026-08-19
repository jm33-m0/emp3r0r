#define spoof_arg(x) ( ULONG_PTR ) ( x )

typedef struct {
    PVOID     ptr;
    int       argc;
    ULONG_PTR args[10];
} FUNCTION_CALL;

ULONG_PTR spoof_call ( FUNCTION_CALL * call );
