/* Test BOF using the Windows BOF import convention: the loader resolves
 * `KERNEL32$VirtualAlloc` to the guest runtime's VirtualAlloc. */
extern void BeaconPrintf(int type, const char *fmt, ...);
extern void *KERNEL32$VirtualAlloc(void *addr, unsigned size, unsigned type,
                                   unsigned prot);

int go(char *args, int len) {
  (void)args;
  (void)len;
  void *p = KERNEL32$VirtualAlloc(0, 16, 0x3000, 4);
  BeaconPrintf(0, "win %s", p != 0 ? "ok" : "no");
  return 0;
}
