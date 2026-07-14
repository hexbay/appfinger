package fetch

import (
	"fmt"
	"time"

	"github.com/robertkrimen/otto"
)

// 默认JavaScript执行的堆栈深度限制
var DefaultStackDepthLimit = 300

// 执行 JavaScript 脚本并设置超时时间，并处理可能的panic
func runScriptWithTimeout(vm *otto.Otto, script string, timeout time.Duration) error {
	done := make(chan error, 1)

	// 设置脚本执行的最大指令数，防止无限循环
	vm.SetStackDepthLimit(DefaultStackDepthLimit) // 使用全局配置的堆栈深度限制

	go func() {
		defer func() {
			if r := recover(); r != nil {
				switch r := r.(type) {
				case error:
					done <- fmt.Errorf("script execution panicked: %v", r)
				default:
					done <- fmt.Errorf("script execution panicked: %v", r)
				}
			}
		}()

		// 尝试安全执行脚本
		_, err := vm.Run(script)
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("script execution timed out")
	}
}
