package modules

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// moduleWatch is the singleton hot-reload watcher. It watches every module
// search dir (and their subdirectories, recursively) and, whenever anything
// under them changes, re-syncs the module registries with what is on disk —
// loading newly added modules, reloading edited ones, and dropping removed
// ones — while logging only the modules that actually changed.
type moduleWatch struct {
	mu sync.Mutex

	// watcher re-arms itself after Close; the quit channel makes Stop return
	// without waiting for the next event.
	quit    chan struct{}
	stopped bool
	running bool
	done    sync.WaitGroup

	// fsnotify handle, set up synchronously by StartModuleWatch
	watcher *fsnotify.Watcher

	// module dir -> sha256 of its config.json content ("" = no config). This
	// is the source of truth for “did this module change?” so a full rescan
	// after any fsnotify event never logs modules whose config is untouched.
	state map[string]string
}

var moduleWatcher = &moduleWatch{
	quit:  make(chan struct{}),
	state: make(map[string]string),
}

// StartModuleWatch launches the module hot-reload watcher in the background.
// The watcher is fully set up (fsnotify handle + recursive watches + state
// seeded from disk) before this returns, so no event that happens after the
// call can be mistaken for pre-existing state. It is safe to call multiple
// times: only the first call starts a watcher (a stopped one is restarted).
func StartModuleWatch() {
	moduleWatcher.mu.Lock()
	if !moduleWatcher.stopped && moduleWatcher.running {
		moduleWatcher.mu.Unlock()
		return
	}
	if moduleWatcher.stopped {
		moduleWatcher.quit = make(chan struct{})
		moduleWatcher.stopped = false
	}
	w := moduleWatcher
	moduleWatcher.mu.Unlock()

	// snapshot the disk state before we start consuming events, so the first
	// reconcile after startup only reports changes that happen from here on
	w.seedState()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logging.Errorf("Module watch: cannot create fsnotify watcher: %v", err)
		return
	}

	w.mu.Lock()
	w.watcher = watcher
	w.mu.Unlock()

	for _, dir := range live.ModuleDirs {
		if !walkAndWatch(watcher, dir) {
			logging.Debugf("Module watch: cannot watch %s", dir)
		}
	}
	if len(watcher.WatchList()) == 0 {
		logging.Debugf("Module watch: no module dirs found to watch")
	}

	w.mu.Lock()
	w.running = true
	w.mu.Unlock()
	moduleWatcher.done.Add(1)
	go w.runLoop()
}

// StopModuleWatch stops the module watcher (used by tests). A subsequent
// StartModuleWatch restarts it.
func StopModuleWatch() {
	moduleWatcher.mu.Lock()
	if moduleWatcher.stopped || !moduleWatcher.running {
		moduleWatcher.mu.Unlock()
		return
	}
	moduleWatcher.stopped = true
	moduleWatcher.running = false
	close(moduleWatcher.quit)
	watcher := moduleWatcher.watcher
	moduleWatcher.mu.Unlock()
	if watcher != nil {
		_ = watcher.Close()
	}
	moduleWatcher.done.Wait()
}

// runLoop consumes fsnotify events and drives the debounced reconcile. The
// watcher handle and the initial watches were already set up by
// StartModuleWatch before this goroutine started.
func (w *moduleWatch) runLoop() {
	defer w.done.Done()

	watcher := w.watcher
	if watcher == nil {
		return
	}
	defer watcher.Close()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// debounce: batch bursts of events (e.g. an editor save or a module
	// build) into a single reconcile
	debounce := time.NewTimer(0)
	if !debounce.Stop() {
		<-debounce.C
	}
	defer debounce.Stop()
	reconcilePending := false

	for {
		select {
		case <-w.quit:
			return
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logging.Debugf("Module watch: %v", err)
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			logging.Debugf("Module watch: event %v on %s", ev.Op, ev.Name)
			w.handleEvent(watcher, ev)
			reconcilePending = true
			if !debounce.Stop() {
				select {
				case <-debounce.C:
				default:
				}
			}
			debounce.Reset(500 * time.Millisecond)

		case <-debounce.C:
			if reconcilePending {
				reconcilePending = false
				w.reconcile()
			}

		case <-ticker.C:
			// periodic safety net: fsnotify can miss events (e.g. on some
			// network filesystems), and root dirs may be created after startup;
			// a reconcile only logs when something actually changed, so an
			// idle watch stays silent.
			for _, dir := range live.ModuleDirs {
				if utilIsDir(dir) {
					walkAndWatch(watcher, dir)
				}
			}
			w.reconcile()
		}
	}
}

// handleEvent processes one fsnotify event: it keeps the watch subtree in
// sync when directories are created or removed (fsnotify watches are
// non-recursive) and filters out noise. Debouncing is handled by the main
// loop, so this function must be cheap.
func (w *moduleWatch) handleEvent(watcher *fsnotify.Watcher, ev fsnotify.Event) {
	if ev.Op&(fsnotify.Create|fsnotify.Remove|fsnotify.Rename|fsnotify.Write|fsnotify.Chmod) == 0 {
		return
	}

	if ev.Op&fsnotify.Create != 0 {
		if info, err := os.Stat(ev.Name); err == nil && info.IsDir() {
			walkAndWatch(watcher, ev.Name)
		}
	}
	if ev.Op&fsnotify.Remove != 0 {
		// on Linux removing a watched dir also removes its watch; on other
		// platforms we drop it explicitly so we don't error later
		_ = watcher.Remove(ev.Name)
	}
}

// reconcile is the heart of the watcher: after a debounce (or a periodic
// tick) it compares what is on disk with the last-known state and with the
// registries, and applies — and logs — only what changed. The operator
// console picks the changes up automatically because its command tree is
// rebuilt from def.Modules on every prompt/completion cycle.
func (w *moduleWatch) reconcile() {
	changes := w.reconcileOnce()
	if len(changes) == 0 {
		return
	}
	for _, c := range changes {
		logging.Infof("Module %s", c)
	}
}

// seedState records every module dir currently on disk, with the hash of its
// config file, so the first reconcile after startup only reports changes that
// happen after the watcher is running. Using the disk state (rather than the
// registry's resolved config paths) also covers the prefix copy of local/
// buildable modules whose config.Path was rewritten to the workspace copy.
func (w *moduleWatch) seedState() {
	now := make(map[string]string, 64)
	for _, dir := range moduleDirsOnDisk() {
		now[dir] = fingerprintConfig(dir)
	}
	w.mu.Lock()
	w.state = now
	w.mu.Unlock()
}

// moduleDirsOnDisk returns the sorted list of module dirs (directories that
// contain a config.json) present in every module search dir.
func moduleDirsOnDisk() []string {
	seen := make(map[string]bool)
	var dirs []string
	for _, searchDir := range live.ModuleDirs {
		if !utilIsDir(searchDir) {
			continue
		}
		entries, err := os.ReadDir(searchDir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			modDir := filepath.Join(searchDir, ent.Name())
			cfg := filepath.Join(modDir, "config.json")
			if !fileExists(cfg) {
				continue
			}
			abs, _ := filepath.Abs(modDir)
			if abs == "" || seen[abs] {
				continue
			}
			seen[abs] = true
			dirs = append(dirs, abs)
		}
	}
	sort.Strings(dirs)
	return dirs
}

// reconcileOnce applies disk changes and returns a human-readable list of
// what changed, one entry per module dir (the caller decides how to log it).
// It is idempotent: running it when nothing changed returns nil.
func (w *moduleWatch) reconcileOnce() []string {
	var changes []string
	var errs []string

	// snapshot disk state
	disk := make(map[string]string)
	for _, dir := range moduleDirsOnDisk() {
		disk[dir] = fingerprintConfig(dir)
	}

	// dirs we tracked but that no longer exist (or lost their config):
	// unregister their modules, then re-establish any module that is still
	// declared by another dir (e.g. deleting the workspace shadow of a module
	// that also ships in the install prefix must not unload it)
	removedDirs := make([]string, 0)
	w.mu.Lock()
	for dir, oldFP := range w.state {
		if _, exists := disk[dir]; !exists && oldFP != "" {
			removedDirs = append(removedDirs, dir)
		}
	}
	w.mu.Unlock()

	restore := make(map[string]bool) // module names to look up elsewhere
	for _, dir := range removedDirs {
		names := unregisterModuleConfigs(dir)
		if len(names) > 0 {
			changes = append(changes, fmt.Sprintf("removed: %s", strings.Join(names, ", ")))
			for _, n := range names {
				restore[n] = true
			}
		}
	}

	// dirs whose config changed (or appeared): reload / load
	// compute the verb before updating the state map below
	type action struct {
		dir string
		fp  string
		add bool // was not tracked before => newly added module
	}
	actions := make([]action, 0)
	for dir, fp := range disk {
		w.mu.Lock()
		oldFP := w.state[dir]
		w.mu.Unlock()
		if fp == oldFP {
			continue
		}
		actions = append(actions, action{dir: dir, fp: fp, add: oldFP == ""})
	}

	// a removed module may still exist in another module dir: loading that
	// dir re-registers it (loadModuleDir is idempotent and only the changed
	// dirs above are reported as added/reloaded)
	for name := range restore {
		for _, dir := range moduleDirsDeclaring(name) {
			if _, ok := disk[dir]; !ok {
				continue
			}
			if _, err := loadModuleDir(dir); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", dir, err))
			}
			break
		}
	}

	type loadedMod struct {
		a     action
		names []string
	}
	var loaded []loadedMod
	for _, a := range actions {
		// editing a config may have removed/renamed entries: drop the dir's
		// previous registrations before re-registering from the new config
		if !a.add {
			unregisterModuleConfigs(a.dir)
		}
		names, err := loadModuleDir(a.dir)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", a.dir, err))
			continue
		}
		loaded = append(loaded, loadedMod{a: a, names: names})
	}

	// re-sync the state map with the disk. Doing this wholesale (rather than
	// only for the dirs we touched) also absorbs side effects of our own
	// actions — copying a buildable module's sources into the workspace fires
	// fsnotify events that must not be reported as module changes on the next
	// reconcile.
	w.seedState()

	// log only what actually changed: a config that was edited or added is
	// reported with the module names it declares; failures are always logged.
	for _, lm := range loaded {
		verb := "reloaded"
		if lm.a.add {
			verb = "loaded"
		}
		if len(lm.names) == 0 {
			changes = append(changes, fmt.Sprintf("%s: module dir %s", verb, lm.a.dir))
			continue
		}
		for _, n := range lm.names {
			changes = append(changes, fmt.Sprintf("%s: %s (from %s)", verb, n, lm.a.dir))
		}
	}
	for _, e := range errs {
		logging.Warningf("Module reload error: %s", e)
	}

	return changes
}

// moduleDirsDeclaring returns every on-disk module dir (in live.ModuleDirs)
// whose config.json declares a module named exactly name.
func moduleDirsDeclaring(name string) []string {
	var dirs []string
	for _, searchDir := range live.ModuleDirs {
		if !utilIsDir(searchDir) {
			continue
		}
		entries, err := os.ReadDir(searchDir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			modDir := filepath.Join(searchDir, ent.Name())
			cfg := filepath.Join(modDir, "config.json")
			if !fileExists(cfg) {
				continue
			}
			configs, err := readModConfigs(cfg)
			if err != nil {
				continue
			}
			for _, c := range configs {
				if c != nil && strings.EqualFold(c.Name, name) {
					dirs = append(dirs, modDir)
					break
				}
			}
		}
	}
	return dirs
}

// walkAndWatch watches dir and, recursively, every subdirectory under it.
// Returns false if dir does not exist or cannot be watched.
func walkAndWatch(watcher *fsnotify.Watcher, dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if wErr := watcher.Add(path); wErr == nil {
			found = true
		}
		return nil
	})
	return found
}

// fingerprintConfig returns a sha256 fingerprint of dir/config.json content,
// or "" when the file does not exist (so an existing config vs a missing one
// always differ).
func fingerprintConfig(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func utilIsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
