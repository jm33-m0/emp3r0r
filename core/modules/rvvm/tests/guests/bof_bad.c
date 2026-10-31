/* Test BOF with an import the runtime does not provide: the loader must report
 * "unresolved symbol no_such_symbol" instead of running it. */
extern void no_such_symbol(void);

int go(char *args, int len) {
  (void)args;
  (void)len;
  no_such_symbol();
  return 0;
}
