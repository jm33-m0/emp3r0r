# kkyum — load the signed kkyum kernel driver via the in-memory driver loader.
#
# This is a multi-file module (config.json):
#   "files": ["kkyum.star", "8516410b49bb79c08c19a37c516dad72.sys"],
#   "module_files_memfs": true
#
# kkyum.star is the entry point (files[0]). The driver image is a companion
# file: the module loader uploads it and caches it in encrypted memfs before
# this script runs, and the `module_files` global lists its mem:/// path.
# read_file() reads it straight out of memfs, so the driver image never
# touches disk as plaintext.
#
# The driver APIs (driver_load_bytes / driver_unload / driver_is_loaded) wrap
# core/lib/driver, which installs the service key and starts the driver with
# NtLoadDriver through the indirect syscall table. Only signed drivers can be
# loaded; an unsigned image is rejected by the kernel.


def find_driver_image():
    for path in module_files:
        if path.endswith(".sys"):
            return read_file(path)
    return None


def main(*args):
    action = args[0] if len(args) > 0 else "load"
    service = args[1] if len(args) > 1 else "kkyum"

    if action == "status":
        if driver_is_loaded(service):
            return "OK: %s is loaded" % service
        return "OK: %s is not loaded" % service

    if action == "unload":
        if not driver_is_loaded(service):
            return "OK: %s is not loaded" % service
        driver_unload(service)
        return "OK: %s unloaded" % service

    if action != "load":
        return "Fail: unknown action %s (use load, unload or status)" % action

    if len(module_files) == 0:
        return "Fail: no companion files uploaded (is module_files_memfs enabled in config.json?)"

    if driver_is_loaded(service):
        return "OK: %s is already loaded" % service

    image = find_driver_image()
    if image == None:
        return "Fail: no .sys driver image found in module_files"

    print("Loading driver %s from memfs (%d bytes)" % (service, len(image)))
    driver_load_bytes(image, service)
    if not driver_is_loaded(service):
        return "Fail: %s did not load (driver must be signed and privileges held)" % service
    return "OK: %s loaded" % service
