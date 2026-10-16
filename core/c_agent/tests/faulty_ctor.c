/*
 * faulty_ctor.c — shared object whose constructor dereferences a bad pointer.
 *
 * test_elfload maps this image, so the loader's crash guard must catch the
 * SIGSEGV and reject the image instead of killing the test process.
 */

__attribute__((constructor)) static void faulty_ctor(void) {
  volatile int *p = (volatile int *)1;
  *p = 1;
}
