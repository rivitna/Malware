package main


import (
  "os"
  "io"
  "io/fs"
  "log"
  "fmt"
  "time"
  "path/filepath"
  "runtime"
  "sync"
  "strings"
  "sort"

  "hive_decrypt/hive"
)


// Log file name
const LogName string = "encr.log"
// Output file name
const OutputFileName string = "encrypted.txt"


// ScanContext structure
type ScanContext struct {
  RansomExt     string
  RansomKeyExt  string
  NumWorkers    int
  ExcludeDirs   []string
}


// XORKeyEntry structure
type XORKeyEntry struct {
  IDExtPart  string
  Key1Pos    uint32
  Key2Pos    uint32
  MaxLen     uint32
  NumFiles   uint
}


// ScanStatus structure
type ScanStatus struct {
  sync.Mutex
  NumEncrypted  uint
  NumErrors     uint
  Keys          []XORKeyEntry
  OutputFile   *os.File
}


// File name channel buffer size
const FilenameChanBufSize = 0x10000


// Main
func main() {

  if (len(os.Args) < 2) {
    fmt.Println("Usage: " + filepath.Base(os.Args[0]) +
                " ransom_ext [path1] [path2] ... [pathN]")
    os.Exit(0)
  }

  ransomExt := os.Args[1]
  if len(ransomExt) != hive.RansomExtLen {
    fmt.Println("Error: Invalid ransom extension")
    os.Exit(1)
  }

  t1 := time.Now()

  logName, _ := os.Hostname()
  if logName != "" {
    logName += "_"
  }
  logName += LogName

  log.SetFlags(0)

  logFile, err := os.OpenFile(logName, os.O_CREATE | os.O_TRUNC | os.O_RDWR,
                              0666)
  if err != nil {

    fmt.Println("Error:", err.Error())

    log.SetOutput(os.Stdout)

  } else {

    defer logFile.Close()

    mw := io.MultiWriter(os.Stdout, logFile)
    log.SetOutput(mw)
  }

  // Prepare system settings
  SysInit()

  ctx := new(ScanContext)
  ctx.RansomExt = string(hive.RansomExtSeparator) + ransomExt
  ctx.RansomKeyExt = string(hive.RansomExtSeparator) + hive.KeyExt +
                     ctx.RansomExt
  ctx.NumWorkers = 2 * runtime.NumCPU()

  // Get default exclude directory list
  ctx.ExcludeDirs = GetDefaultExcludeDirs()

  // Scan exported keys
  ctx.ScanExportedKeys()

  // Scan files
  c := ctx.ScanFiles()

  // Process files
  ctx.ProcessFiles(c)

  t2 := time.Now()
  elapsed := t2.Sub(t1)

  log.Println("Elapsed:", elapsed)
}


// Scan exported keys
func (ctx *ScanContext) ScanExportedKeys() {

  log.Println("Scan exported keys...")

  numKeys := 0

  // Get fixed drive list
  drives := GetFixedDrives()

  for _, drive := range drives {
    // Scan exported keys in directory
    numKeys += ctx.ScanDirExportedKeys(drive)
  }

  if numKeys == 0 {
    log.Println("Warning:", "Exported keys not found")
  }
}


// Scan exported keys in directory
func (ctx *ScanContext) ScanDirExportedKeys(dirPath string) int {

  f, err := os.Open(dirPath)
  if err != nil {
    log.Println("Error:", err.Error())
    return 0
  }
  defer f.Close()

  files, err := f.ReadDir(-1)
  if err != nil {
    log.Println("Error:", err.Error())
    return 0
  }

  numKeys := 0

  for _, file := range files {

    if file.IsDir() || !strings.HasSuffix(file.Name(), ctx.RansomKeyExt) {
      continue
    }

    // Analyze exported key file name
    keyPath := filepath.Join(dirPath, file.Name())
    keyTabHash, err := hive.AnalyzeExportedKeyFilename(keyPath)
    if err != nil {
      log.Println("Error:", err.Error())
      continue
    }

    log.Println(keyPath)
    log.Printf("Key table hash: %x", keyTabHash)

    numKeys++

    fileInfo, err := os.Stat(keyPath)
    if err != nil {
      log.Println("Error:", err.Error())
      continue
    }

    keySize := fileInfo.Size()

    log.Printf("Exported key size: %d", keySize)

    if keySize <= hive.EncKeyTabSize {
      log.Println("Error:", "Invalid exported key size")
    }
  }

  return numKeys
}


// Scan files
func (ctx *ScanContext) ScanFiles() <- chan string {

  log.Println("Scan files...")

  var pathList []string

  if (len(os.Args) < 3) {
    // Get default scan path list
    pathList = GetDefaultScanPaths()
  } else {
    pathList = os.Args[2:]
  }

  for _, path := range pathList {
    log.Println("Scan path:", path)
  }

  c := make(chan string, FilenameChanBufSize)

  go func() {
    defer close(c)

    for _, path := range pathList {
      ctx.ScanPath(path, c)
    }
  }()

  return c
}


// Scan path
func (ctx *ScanContext) ScanPath(path string, c chan <- string) {

  var walkDirFn = func(path string, d fs.DirEntry, err error) error {

    if err != nil {
      log.Println("Error:", err.Error())
      return nil
    }

    if d.IsDir() {

      for _, excludeDir := range ctx.ExcludeDirs {

        if filepath.IsAbs(excludeDir) {
          if strings.EqualFold(path, excludeDir) {
            log.Println("Skipped:", path)
            return fs.SkipDir
          }
        }
      }

      return nil
    }

    if strings.HasSuffix(path, ctx.RansomExt) && 
       !strings.HasSuffix(path, ctx.RansomKeyExt) {
      c <- path
    }

    return nil
  }

  fullPath, err := filepath.Abs(path)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }

  fileInfo, err := os.Stat(fullPath)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }

  if fileInfo.IsDir() {
    filepath.WalkDir(fullPath, walkDirFn)
  } else {
    c <- fullPath
  }
}


// Process files
func (ctx *ScanContext) ProcessFiles(c <- chan string) {

  var stat ScanStatus

  outputFile, err := os.OpenFile(OutputFileName,
                                 os.O_CREATE | os.O_TRUNC | os.O_RDWR,
                                 0666)
  if err != nil {
    log.Println("Error:", err.Error())
  } else {
    stat.OutputFile = outputFile
  }
  defer outputFile.Close()

  var wg sync.WaitGroup

  for i := 0; i < ctx.NumWorkers; i++ {
    wg.Add(1)
    go ctx.ProcessFileWorker(&wg, c, &stat)
  }

  wg.Wait()

  log.Printf("=====================")
  log.Printf("Encrypted: %10d", stat.NumEncrypted)
  log.Printf("Errors:    %10d", stat.NumErrors)
  log.Printf("Keys:      %10d", len(stat.Keys))
  log.Printf("=====================")

  // Sort keys by number of files
  sort.Slice(stat.Keys,
             func(i, j int) bool {
               return (stat.Keys[i].NumFiles > stat.Keys[j].NumFiles)
             })

  if len(stat.Keys) != 0 {

    log.Println("Keys:")

    for _, keyInfo := range stat.Keys {
      log.Printf("%s %08X %08X %08d (%d)",
                 keyInfo.IDExtPart, keyInfo.Key1Pos, keyInfo.Key2Pos,
                 keyInfo.MaxLen, keyInfo.NumFiles)
    }

    log.Println()
  }
}


// Log error
func LogError(err error, stat *ScanStatus) {

  stat.Lock()
  stat.NumErrors++
  stat.Unlock()

  log.Println("Error:", err.Error())
}


// Process file
func (ctx *ScanContext) ProcessFileWorker(wg *sync.WaitGroup,
                                          c <- chan string,
                                          stat *ScanStatus) {

  defer wg.Done()

  for fileName := range c {

    // Analyze encrypted file
    info, err := hive.AnalyzeEncFile(fileName)
    if err != nil {
      // Log error
      LogError(err, stat)
      continue
    }

    stat.Lock()
    stat.NumEncrypted++
    stat.Unlock()

    log.Println("Encrypted:", fileName)

    // Update XOR key list
    stat.UpdateXORKeys(fileName, info)

    if stat.OutputFile == nil {
      continue
    }

    // Get Hive hash
    hash, err := hive.GetHiveHash(fileName, false)
    if err != nil {
      // Log error
      LogError(err, stat)
      continue
    }

    s := fmt.Sprintf("%x\t%s\n", hash, fileName)
    stat.Lock()
    stat.OutputFile.WriteString(s)
    stat.Unlock()
  } 
}


// Update XOR key list
func (stat *ScanStatus) UpdateXORKeys(filePath string,
                                      info *hive.EncryptedFileInfo) {

  keyIDExtPart := hive.GetKeyIDExtPart(filePath)
  keyLen := uint32(info.NumBlocks * hive.BlockSize)

  stat.Lock()
  defer stat.Unlock()

  for i := range stat.Keys {

    if keyIDExtPart != stat.Keys[i].IDExtPart {
      continue
    }

    if keyLen > stat.Keys[i].MaxLen {
      stat.Keys[i].MaxLen = keyLen
    }

    stat.Keys[i].NumFiles++
    return
  }

  keyEntry := XORKeyEntry{keyIDExtPart,
                          hive.GetKey1Pos(info.N1),
                          hive.GetKey2Pos(info.N2),
                          keyLen, 1}
  stat.Keys = append(stat.Keys, keyEntry)
}
