package agent

// TODO

// PersistMethods CC calls one of these methods to get persistence, or all of them at once
var PersistMethods = map[string]func() error{
	"all":        allInOne,
	"ld_preload": ldPreload,
	"profiles":   profiles,
	"service":    service,
	"injector":   injector,
	"task":       task,
	"patcher":    patcher,
}

// allInOne called by ccHandler
func allInOne() (err error) {
	return
}

func profiles() (err error) {
	return
}

func ldPreload() (err error) {
	return
}

func injector() (err error) {
	return
}

func service() (err error) {
	return
}

func task() (err error) {
	return
}

func patcher() (err error) {
	return
}
