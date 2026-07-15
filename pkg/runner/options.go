package runner

// Options 运行时配置选项
type Options struct {
	// 输入相关
	Target  string   // 单个目标URL
	Targets []string // 多个目标URL列表
	File    string   // 目标文件路径
	Stdin   bool     // 是否使用标准输入
	// 运行相关
	Threads  int    // 并发线程数
	Timeout  int    // 超时时间（秒）
	Verbose  bool   // 是否输出详细信息
	Silent   bool   // 是否静默模式
	RulePath string // 规则库路径

	// 输出相关
	Output    string // 输出文件路径
	JSON      bool   // 是否输出JSON格式
	NoColor   bool   // 是否禁用彩色输出
	OutputAll bool   // 是否输出所有结果（包括未识别到指纹的目标）
	// 回调函数，用于处理扫描结果
	Callback func(target string, result *Result)
}

// DefaultOptions 默认配置选项
var DefaultOptions = Options{
	Threads: 10,
	Timeout: 30,
}

func defaultOptions() *Options {
	options := DefaultOptions
	return &options
}
