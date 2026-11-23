//go:build !windows

package common

import "os"

func replaceFileAtomic(src, dst string) error {
	return os.Rename(src, dst)
}
