/* Test BOF that calls a separately delivered RISC-V library. */
extern int answer(void);
extern void BeaconPrintf(int type, const char *fmt, ...);

int go(char *args, int len) {
  (void)args;
  (void)len;
  BeaconPrintf(0, "lib %d", answer());
  return 0;
}
