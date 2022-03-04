//go:build !windows
// +build !windows

package main


// Prepare system settings
func SysInit() {
}


// Get default scan path list
func GetDefaultScanPaths() []string {

  pathList := [1]string{"/"}
  return pathList[:]
}


// Get default exclude directory list
func GetDefaultExcludeDirs() []string { return nil }
