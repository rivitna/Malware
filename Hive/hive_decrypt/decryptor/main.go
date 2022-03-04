package main


import (
  "os"
  "io"
  "io/fs"
  "log"
  "flag"
  "fmt"
  "time"
  "path/filepath"
  "runtime"
  "sync"
  "strings"
  "bytes"
  "errors"
  "crypto/sha256"

  "hive_decrypt/hive"
)


// Extended log file name
const ExtLogName string = "decrypted.txt"


// DecryptContext structure
type DecryptContext struct {
  RansomExt        string
  RansomKeyExt     string
  NumWorkers       int
  CmdArgs          []string
  ExcludeDirs      []string
  Keys             []hive.XORKey
  RemoveEncrypted  bool
  ExtLog           bool
  ExtLogFile      *os.File
}


// DecryptStatus structure
type DecryptStatus struct {
  sync.Mutex
  NumEncrypted  uint
  NumDecrypted  uint
  NumErrors     uint
}


// File data buffer size
const FileDataBufSize = 0x10000

// File name channel buffer size
const FilenameChanBufSize = 0x10000


// Main
func main() {

  var removeEncrypted bool
  var extLog bool

  flag.BoolVar(&removeEncrypted, "d", false, "")
  flag.BoolVar(&extLog, "x", false, "")
  flag.Parse()

  cmdArgs := flag.Args()

  if (len(cmdArgs) < 1) {
    fmt.Println("Usage: " + filepath.Base(os.Args[0]) +
                " [-d] [-x] ransom_ext [path1] [path2] ... [pathN]")
    os.Exit(0)
  }

  ransomExt := cmdArgs[0]
  if len(ransomExt) != hive.RansomExtLen {
    fmt.Println("Error: Invalid ransom extension")
    os.Exit(0)
  }

  t1 := time.Now()

  logName, _ := os.Hostname()
  if logName != "" {
    logName += "_"
  }
  logName += t1.Format("20060102150405") + ".log"

  log.SetFlags(log.Ltime)

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

  // Load XOR keys
  keys, _ := LoadXORKeys("keys")
  if len(keys) == 0 {
    log.Fatal("Error: ", "Failed to load keys")
  }

  log.Printf("%d key(s) loaded.", len(keys))

  // Prepare system settings
  SysInit()

  ctx := new(DecryptContext)
  ctx.RansomExt = "." + ransomExt
  ctx.RansomKeyExt = ".key." + ransomExt
  ctx.NumWorkers = 2 * runtime.NumCPU()
  ctx.CmdArgs = cmdArgs
  ctx.RemoveEncrypted = removeEncrypted
  ctx.ExtLog = extLog

  // Get default exclude directory list
  ctx.ExcludeDirs = GetDefaultExcludeDirs()

  ctx.Keys = keys

  // Scan files
  c := ctx.ScanFiles()

  // Decrypt files
  ctx.DecryptFiles(c)

  t2 := time.Now()
  elapsed := t2.Sub(t1)

  log.Println("Elapsed:", elapsed)
}


// Load XOR keys
func LoadXORKeys(dirPath string) (keys []hive.XORKey, err error) {

  f, err := os.Open(dirPath)

  if err != nil {
    return nil, err
  }
  defer f.Close()

  fileList, err := f.ReadDir(-1)
  if err != nil {
    return nil, err
  }

  for _, file := range fileList {

    if file.IsDir() {
      continue
    }

    keyPath := filepath.Join(dirPath, file.Name())

    // Load XOR key from file
    key, err := hive.LoadXORKey(keyPath)
    if err != nil {
      log.Println("Error:", err.Error())
      continue
    }

    fmt.Printf("%x\n", key.KeyTabHash)

    // Add encryption key to list
    if FindKeyInList(keys, key.KeyTabHash, key.Key1Pos, key.Key2Pos) == nil {
      keys = append(keys, *key)
    }
  }

  return keys, nil
}


// Find key in list
func FindKeyInList(keys []hive.XORKey,
                   keyTabHash []byte,
                   key1Pos, key2Pos uint32) *hive.XORKey {

  for i, k := range keys {
    if (key1Pos == k.Key1Pos) && (key2Pos == k.Key2Pos) &&
       bytes.Equal(keyTabHash, k.KeyTabHash) {
      return &keys[i]
    }
  }
  return nil
}


// Scan files
func (ctx *DecryptContext) ScanFiles() <- chan string {

  var pathList []string

  if (len(ctx.CmdArgs) < 2) {
    // Get default scan path list
    pathList = GetDefaultScanPaths()
  } else {
    pathList = ctx.CmdArgs[1:]
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
func (ctx *DecryptContext) ScanPath(path string, c chan <- string) {

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


// Decrypt files
func (ctx *DecryptContext) DecryptFiles(c <- chan string) {

  log.Println("Decrypt files...")

  var stat DecryptStatus

  if ctx.ExtLog {
    extLogFile, err := os.OpenFile(ExtLogName,
                                   os.O_CREATE | os.O_TRUNC | os.O_RDWR,
                                   0666)
    if err != nil {
      log.Println("Error:", err.Error())
    } else {
      ctx.ExtLogFile = extLogFile
    }
    defer extLogFile.Close()
  }

  var wg sync.WaitGroup

  for i := 0; i < ctx.NumWorkers; i++ {
    wg.Add(1)
    go ctx.DecryptFileWorker(&wg, c, &stat)
  }

  wg.Wait()

  log.Printf("=====================")
  log.Printf("Encrypted: %10d", stat.NumEncrypted)
  log.Printf("Decrypted: %10d", stat.NumDecrypted)
  log.Printf("Errors:    %10d", stat.NumErrors)
  log.Printf("=====================")
}


// Log error
func LogError(err error, stat *DecryptStatus) {

  stat.Lock()
  stat.NumErrors++
  stat.Unlock()

  log.Println("Error:", err.Error())
}


// Decrypt file
func (ctx *DecryptContext) DecryptFileWorker(wg *sync.WaitGroup,
                                             c <- chan string,
                                             stat *DecryptStatus) {

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

    // Find key in list
    key1Pos := hive.GetKey1Pos(info.N1)
    key2Pos := hive.GetKey2Pos(info.N2)
    key := FindKeyInList(ctx.Keys, info.KeyTabHash, key1Pos, key2Pos)
    if key == nil {
      // Log error
      LogError(errors.New("Key is missing"), stat)
      continue
    }

    origFilePath := hive.GetOriginalFileName(fileName)

    // Decrypt file
    err = hive.DecryptFile(fileName, origFilePath, ctx.RemoveEncrypted,
                           key.Data)
    if err != nil {
      // Log error
      LogError(err, stat)
      continue
    }

    stat.Lock()
    stat.NumDecrypted++
    stat.Unlock()

    log.Println("Decrypted:", origFilePath)

    if ctx.ExtLogFile != nil {
      // Get file hash
      hash, err := GetFileHash(origFilePath)
      if err != nil {
        // Log error
        LogError(err, stat)
      } else {
        s := fmt.Sprintf("%x\t%s\n", hash, origFilePath)
        ctx.ExtLogFile.WriteString(s)
      }
    }
  } 
}


// Get file hash
func GetFileHash(fileName string) ([]byte, error) {

  f, err := os.Open(fileName)
  if err != nil { return nil, err }
  defer f.Close()

  h := sha256.New()

  if _, err = io.Copy(h, f); err != nil {
    return nil, err
  }

  return h.Sum(nil), nil
}
