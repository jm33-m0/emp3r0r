package runtime_def

type prompt_func func(string) string

var Prompt prompt_func
