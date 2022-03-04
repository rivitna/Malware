package main


import (
  "os"
  "log"
  "strings"
  "syscall"
  "unsafe"
  "unicode/utf16"
)


// Prepare system settings
func SysInit() {

  // Enable privilege SeBackupPrivilege
  err := WinEnablePriv("SeBackupPrivilege", true)
  if err != nil {
    log.Println("Error:", err.Error())
  }
}


// Get default scan path list
func GetDefaultScanPaths() []string {

  // Get fixed and removable drive list (Windows)
  pathList := WinGetDriveList(12)
  if len(pathList) == 0 {
    log.Fatal("Error: ", "No drives detected.")
  }

  return pathList
}


// Get default exclude directory list
func GetDefaultExcludeDirs() []string {

  var excludeDirs []string

  winDir, _ := WinGetWinDir()
  if (winDir != "") &&
     !strings.HasSuffix(winDir, string(os.PathListSeparator)) {
    excludeDirs = append(excludeDirs, strings.ToLower(winDir))
  }

  return excludeDirs
}


// Convert NUL-terminated UTF-16 sequence to string
func UTF16ToString(s []uint16) string {
  for i, c := range s {
    if c == 0 {
      s = s[:i]
      break
    }
  }
  return string(utf16.Decode(s))
}


// Get drive list (Windows)
// No root dir    2 (1 << 1)
// Removable      4 (1 << 2)
// Fixed          8 (1 << 3)
// Remote      0x10 (1 << 4)
// CD-ROM      0x20 (1 << 5)
// RAM disk    0x40 (1 << 6)
// Example: Fixed and Remote drives 0x18
func WinGetDriveList(driveTypeMask int) []string {

  hKernel32, err := syscall.LoadLibrary("kernel32.dll")
  if err != nil { return nil }

  pfnGetLogDrives, err := syscall.GetProcAddress(hKernel32,
                                                 "GetLogicalDrives")
  if err != nil { return nil }

  pfnGetDriveType, err := syscall.GetProcAddress(hKernel32, "GetDriveTypeW")
  if err != nil { return nil }

  driveMask, _, _ := syscall.Syscall(uintptr(pfnGetLogDrives), 0, 0, 0, 0)
  if driveMask == 0 { return nil }

  var driveList []string

  for ch := 'A'; (ch <= 'Z') && (driveMask != 0); ch++ {

    if driveMask & 1 != 0 {

      rootPath := string(ch) + ":\\"

      rootPathW, _ := syscall.UTF16PtrFromString(rootPath)

      driveType, _, _ := syscall.Syscall(uintptr(pfnGetDriveType), 1,
                                         uintptr(unsafe.Pointer(rootPathW)),
                                         0, 0)

      if (driveType != 0) {
        if driveTypeMask & (1 << driveType) != 0 {
          driveList = append(driveList, rootPath)
        }
      }
    }

    driveMask >>= 1
  }

  return driveList
}


// Get Windows directory (Windows)
func WinGetWinDir() (string, error) {

  hKernel32, err := syscall.LoadLibrary("kernel32.dll")
  if err != nil { return "", err }

  pfnGetWindowsDirectory, err :=
    syscall.GetProcAddress(hKernel32, "GetSystemWindowsDirectoryW")
  if err != nil {
    pfnGetWindowsDirectory, err =
      syscall.GetProcAddress(hKernel32, "GetWindowsDirectoryW")
    if err != nil { return "", err }
  }

  bufLen := uint32(260)

  bufW := make([]uint16, bufLen)

  ln, _, errno := syscall.Syscall(uintptr(pfnGetWindowsDirectory), 2,
                                  uintptr(unsafe.Pointer(&bufW[0])),
                                  uintptr(bufLen), 0)

  if ln == 0 { return "", errno }

  if uint32(ln) > bufLen {

    bufLen = uint32(ln)

    bufW := make([]uint16, bufLen)

    ln, _, errno := syscall.Syscall(uintptr(pfnGetWindowsDirectory), 2,
                                    uintptr(unsafe.Pointer(&bufW[0])),
                                    uintptr(bufLen), 0)

    if ln == 0 { return "", errno }

    if uint32(ln) > bufLen { return "", syscall.Errno(111) }
  }

  return UTF16ToString(bufW[:ln]), nil
}


// Enable privilege (Windows)
func WinEnablePriv(privName string, enable bool) error {

  hKernel32, err := syscall.LoadLibrary("kernel32.dll")
  if err != nil { return err }

  hAdvapi32, err := syscall.LoadLibrary("advapi32.dll")
  if err != nil { return err }

  pfnCloseHandle, err := syscall.GetProcAddress(hKernel32,
                                                "CloseHandle")
  if err != nil { return err }

  pfnGetCurrentThread, err := syscall.GetProcAddress(hKernel32,
                                                     "GetCurrentThread")
  if err != nil { return err }

  pfnGetCurrentProcess, err := syscall.GetProcAddress(hKernel32,
                                                      "GetCurrentProcess")
  if err != nil { return err }

  pfnOpenThreadToken, err := syscall.GetProcAddress(hAdvapi32,
                                                    "OpenThreadToken")
  if err != nil { return err }

  pfnOpenProcessToken, err := syscall.GetProcAddress(hAdvapi32,
                                                     "OpenProcessToken")
  if err != nil { return err }

  pfnLookupPrivilegeValue, err :=
    syscall.GetProcAddress(hAdvapi32, "LookupPrivilegeValueW")
  if err != nil { return err }

  pfnAdjustTokenPrivileges, err :=
    syscall.GetProcAddress(hAdvapi32, "AdjustTokenPrivileges")
  if err != nil { return err }

  var hToken uintptr

  hThread, _, _ := syscall.Syscall(uintptr(pfnGetCurrentThread), 0, 0, 0, 0)

  ret, _, errno := syscall.Syscall6(uintptr(pfnOpenThreadToken), 4,
                                    uintptr(hThread),
                                    // TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES
                                    uintptr(0x28),
                                    uintptr(0),
                                    uintptr(unsafe.Pointer(&hToken)),
                                    0, 0)

  if ret == 0 {

    if errno != syscall.Errno(1008) { return errno }

    hProcess, _, _ := syscall.Syscall(uintptr(pfnGetCurrentProcess),
                                      0, 0, 0, 0)

    ret, _, errno = syscall.Syscall(uintptr(pfnOpenProcessToken), 3,
                                    uintptr(hProcess),
                                    // TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES
                                    uintptr(0x28),
                                    uintptr(unsafe.Pointer(&hToken)))
    if (ret == 0) { return errno }
  }

  type LUID struct {
    LowPart   uint32
    HighPart  int32
  }

  var luid LUID

  privNameW, _ := syscall.UTF16PtrFromString(privName)

  ret, _, errno = syscall.Syscall(uintptr(pfnLookupPrivilegeValue), 3,
                                  uintptr(0),
                                  uintptr(unsafe.Pointer(privNameW)),
                                  uintptr(unsafe.Pointer(&luid)))

  if ret != 0 {

    type LUIDAndAttributes struct {
      Luid        LUID
      Attributes  uint32
    }

    type TokenPrivileges struct {
      PrivilegeCount  uint32
      Privileges      [1]LUIDAndAttributes
    }

    var tokenPrivileges TokenPrivileges
    tokenPrivileges.PrivilegeCount = 1
    tokenPrivileges.Privileges[0].Luid = luid
    if enable {
      tokenPrivileges.Privileges[0].Attributes = uint32(2)
    }

    ret, _, errno =
      syscall.Syscall6(uintptr(pfnAdjustTokenPrivileges), 6,
                       uintptr(hToken),
                       uintptr(0),
                       uintptr(unsafe.Pointer(&tokenPrivileges)),
                       uintptr(unsafe.Sizeof(tokenPrivileges)),
                       uintptr(0),
                       uintptr(0))
  }

  syscall.Syscall(uintptr(pfnCloseHandle), 1, uintptr(hToken), 0, 0)

  if ret == 0 { return errno }

  return nil
}
