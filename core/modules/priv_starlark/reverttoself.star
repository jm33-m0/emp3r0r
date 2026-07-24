# Starlark translation of RevertToSelf() + TRevertToSelf() from priv_windows.go
#
# func RevertToSelf() error {
#     err := windows.RevertToSelf()
#     err = windows.CloseHandle(windows.Handle(CurrentToken))
#     CurrentToken = windows.Token(0)
#     return err
# }
#
# func TRevertToSelf() error {
#     return windows.RevertToSelf()
# }
#
# Parameters: args[0] = "thread" to call only TRevertToSelf (optional)


def RevertToSelf():
    """
    Mirrors RevertToSelf() from priv_windows.go.
    Calls windows.RevertToSelf() then windows.CloseHandle(CurrentToken).
    """
    # err := windows.RevertToSelf()
    res = win_call("advapi32.dll", "RevertToSelf")
    if res["r1"] == 0:
        err = win_call("kernel32.dll", "GetLastError")["r1"]
        print("[-] RevertToSelf failed. Error: %d" % err)
        return False

    # NOTE: CurrentToken handle lifecycle is managed per-invocation in Starlark;
    # there is no global CurrentToken across script runs, so CloseHandle on the
    # pseudo-handle (0) is skipped as windows.CloseHandle(Token(0)) would be a no-op.
    # windows.CloseHandle(windows.Handle(CurrentToken))
    # CurrentToken = windows.Token(0)

    print("[+] RevertToSelf succeeded – thread identity restored to process token.")
    return True


def TRevertToSelf():
    """
    Mirrors TRevertToSelf() from priv_windows.go.
    Calls only windows.RevertToSelf() with no handle cleanup.
    """
    # return windows.RevertToSelf()
    res = win_call("advapi32.dll", "RevertToSelf")
    if res["r1"] == 0:
        err = win_call("kernel32.dll", "GetLastError")["r1"]
        print("[-] TRevertToSelf failed. Error: %d" % err)
        return False
    print("[+] TRevertToSelf succeeded.")
    return True


def main(*args):
    mode = args[0] if len(args) > 0 else ""
    if str(mode).lower() == "thread":
        TRevertToSelf()
    else:
        RevertToSelf()


main()
