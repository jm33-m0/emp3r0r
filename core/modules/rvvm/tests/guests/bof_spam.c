/* Test BOF: writes until the interpreter's output buffer is full, so the
 * output limit path is exercised instead of a successful run. */
extern void BeaconOutput(int type, const char *data, int len);

int go(char *args, int len) {
  (void)args;
  (void)len;
  for (;;)
    BeaconOutput(0, "0123456789abcdef", 16);
  return 0;
}
