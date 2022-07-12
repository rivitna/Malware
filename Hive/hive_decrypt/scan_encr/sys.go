//go:build !windows
// +build !windows

package main


import (
  "os"
)


// Prepare system settings
func SysInit() {
}


// Get default scan path list
func GetDefaultScanPaths() []string {

  pathList := [1]string{"/"}
  return pathList[:]
}


// Get fixed drive list
func GetFixedDrives() []string {

  driveList := [1]string{"/"}
  return driveList[:]
}


// Get default exclude directory list
func GetDefaultExcludeDirs() []string { return nil }


// Check if the file/directory has an associated reparse point,
// or the file is a symbolic link
func IsSymlink(fileName string) (bool, error) {

  fileInfo, err := os.Stat(fileName)
  if err != nil { return false, err }

  return (fileInfo.Mode() & os.ModeSymlink == os.ModeSymlink), nil
}
