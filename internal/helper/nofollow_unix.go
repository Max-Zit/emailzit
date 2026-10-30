//go:build !windows

package helper

import "syscall"

// noFollow makes OpenFile refuse a symbolic link.
const noFollow = syscall.O_NOFOLLOW
