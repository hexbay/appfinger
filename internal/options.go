package internal

import (
	"fmt"
	"io"
	"os"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/hexbay/appfinger/pkg/external/customrules"
)

type Options struct {
	UrlFile           string
	URL               goflags.StringSlice
	Threads           int
	Timeout           int
	Proxy             string
	Output            io.Writer
	OutputFile        string
	OutputType        string
	Stdin             bool
	FingerHome        string
	Debug             bool
	UpdateRule        bool
	DisableIcon       bool
	DisableJavaScript bool
	Version           bool
	DebugResp         bool
	DebugReq          bool
	Validate          bool
}

func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`AppFinger is a web application fingerprint scanner.`)
	flagSet.CreateGroup("AppFinger", "AppFinger",
		flagSet.StringVarP(&options.UrlFile, "url-file", "l", "", "File containing urls to scan"),
		flagSet.StringSliceVarP(&options.URL, "url", "u", nil, "target url to scan (-u INPUT1 -u INPUT2)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.IntVarP(&options.Threads, "threads", "t", 10, "Number of concurrent threads (default 10)"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "Timeout in seconds (default 10)"),
		flagSet.StringVarP(&options.Proxy, "proxy", "x", "", "HTTP proxy to use for requests (e.g. http://127.0.0.1:7890)"),
		flagSet.BoolVarP(&options.Stdin, "stdin", "s", false, "Read urls from stdin"),
		flagSet.StringVarP(&options.FingerHome, "finger-home", "d", customrules.GetDefaultDirectory(), "finger yaml directory home default is built-in"),
		flagSet.BoolVarP(&options.UpdateRule, "update-rule", "ur", false, "update rule from github.com/hexbay/appfinger"),
		flagSet.BoolVarP(&options.DisableIcon, "disable-icon", "di", false, "disabled icon request to matcher"),
		flagSet.BoolVarP(&options.DisableJavaScript, "disable-js", "dj", false, "disabled matcher javascript rule"),
		flagSet.BoolVar(&options.DebugResp, "debug-resp", false, "debug response"),
		flagSet.BoolVar(&options.DebugReq, "debug-req", false, "debug request"),
		flagSet.BoolVarP(&options.Version, "version", "v", false, "show version"),
		flagSet.BoolVar(&options.Validate, "validate", false, "validate rules and exit"),
	)
	flagSet.CreateGroup("Help", "Help",
		flagSet.BoolVar(&options.Debug, "debug", false, "debug"),
	)
	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output to"),
		flagSet.StringVar(&options.OutputType, "output-format", "txt", "输出文件格式"),
	)
	if err := flagSet.Parse(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	if !options.UpdateRule && !options.Version && !options.Validate {
		if len(options.URL) == 0 && options.UrlFile == "" && !options.Stdin {
			gologger.Error().Msgf("Not Set Target")
		}
	}
	return options
}
