//go:build !windows

package wxkey

func runImageKey(root string) (*ImageKeyResult, string, error) {
	return runImageKeyExternal(root)
}
