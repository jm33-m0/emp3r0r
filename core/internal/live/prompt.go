package live

type prompt_func func(string) string

var Prompt prompt_func
