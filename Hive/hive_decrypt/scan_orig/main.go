package main


import (
  "os"
  "io"
  "io/fs"
  "bufio"
  "log"
  "fmt"
  "time"
  "path/filepath"
  "runtime"
  "sync"
  "bytes"
  "strings"
  "errors"
  "encoding/hex"

  "hive_decrypt/hive"
)


// Original file directory name
const OrigFileDirName string = "original"
// Intput file name
const InputFileName string = "encrypted.txt"
// Output file name
const OutputFileName string = "original.txt"
// Output #2 file name
const OutputFileName2 string = "need_encr.txt"
// Log file name
const LogName string = "orig.log"


// EncFileEntry structure
type EncFileEntry struct {
  Key1Pos  uint32
  Key2Pos  uint32
  Hash     []byte
}


// XORKeyID structure
type XORKeyID struct {
  Key1Pos  uint32
  Key2Pos  uint32
}


// OrigFileEntry structure
type OrigFileEntry struct {
  Path  string
  Size  int64
  Hash  []byte
}


// ScanContext structure
type ScanContext struct {
  NumWorkers   int
  ExcludeDirs  []string
  EncFiles     []EncFileEntry
}


// ScanStatus structure
type ScanStatus struct {
  sync.Mutex
  NumFiles      uint
  NumOriginals  uint
  NumCopied     uint
  NumErrors     uint
  OrigFiles     map[XORKeyID][]OrigFileEntry
}


// Max number of original files per key
const MaxOrigFilesPerKey = 5

// File name channel buffer size
const FilenameChanBufSize = 0x10000


// Main
func main() {

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

  // Import encrypted file list
  encFiles, err := ImportEncFileList()
  if err != nil {
    log.Fatal("Error: ", err.Error())
  }
  numEncFiles := len(encFiles)
  if numEncFiles == 0 {
    log.Fatal("Encrypted file list is empty")
  }
  log.Printf("Encrypted files: %d", numEncFiles)
  log.Printf("Encryption keys: %d", CalcNumXORKeys(encFiles))

  // Prepare system settings
  SysInit()

  ctx := new(ScanContext)
  ctx.NumWorkers = 2 * runtime.NumCPU()
  ctx.EncFiles = encFiles

  // Scan files
  c := ctx.ScanFiles()

  // Process files
  ctx.ProcessFiles(c)

  t2 := time.Now()
  elapsed := t2.Sub(t1)

  log.Println("Elapsed:", elapsed)
}


// Import encrypted file list
func ImportEncFileList() (list []EncFileEntry, err error) {

  log.Println("Import encrypted file list...")

  f, err := os.Open(InputFileName)
  if err != nil { return nil, err }
  defer f.Close()

  reader := bufio.NewReader(f)

  for {

    line, _, err := reader.ReadLine()
    if err != nil {
      if err == io.EOF {
        err = nil
      }
      break
    }

    // Parse encrypted file info
    entry, _, err := ParseEncFileEntry(string(line))
    if err != nil {
      log.Printf("Error: Failed to parse encrypted file info (%s)",
                 err.Error())
    } else {
      list = append(list, *entry)
    }
  }

  return list, err
}


// Parse encrypted file entry
func ParseEncFileEntry(s string) (entry *EncFileEntry,
                                  encFilePath string,
                                  err error) {

  if len(s) <= 2 * hive.EncKeyTabHashSize {
    return nil, "", errors.New("Too small string")
  }

  hash, err := hex.DecodeString(s[:2 * hive.EncKeyTabHashSize])
  if err != nil { return nil, "", err }

  filePath := strings.TrimSpace(s[2 * hive.EncKeyTabHashSize:])

  var info hive.EncryptedFileInfo

  // Analyze encrypted file name
  err = info.AnalyzeEncFilename(filePath)
  if err != nil { return nil, filePath, err }

  entry = &EncFileEntry{hive.GetKey1Pos(info.N1),
                        hive.GetKey2Pos(info.N2),
                        hash}
  return entry, filePath, nil
}


// Calculate number of XOR keys
func CalcNumXORKeys(encFiles []EncFileEntry) int {

  keys := make(map[XORKeyID]struct{})

  for _, entry := range encFiles {
    keys[XORKeyID{entry.Key1Pos, entry.Key2Pos}] = struct{}{}
  }

  return len(keys)
}


// Scan files
func (ctx *ScanContext) ScanFiles() <- chan string {

  log.Println("Scan files...")

  var pathList []string

  if (len(os.Args) < 2) {
    // Get default scan path list
    pathList = GetDefaultScanPaths()
  } else {
    pathList = os.Args[1:]
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

    c <- path

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

  stat.OrigFiles = make(map[XORKeyID][]OrigFileEntry)

  var wg sync.WaitGroup

  for i := 0; i < ctx.NumWorkers; i++ {
    wg.Add(1)
    go ctx.ProcessFileWorker(&wg, c, &stat)
  }

  wg.Wait()

  // Save original file list
  stat.SaveOriginalFileList()

  // Copy original files
  stat.CopyOriginalFiles()

  // Export encrypted file list
  stat.ExportEncFileList()

  log.Printf("=====================")
  log.Printf("Files:     %10d", stat.NumFiles)
  log.Printf("Originals: %10d", stat.NumOriginals)
  log.Printf("Copied:    %10d", stat.NumCopied)
  log.Printf("Keys:      %10d", len(stat.OrigFiles))
  log.Printf("Errors:    %10d", stat.NumErrors)
  log.Printf("=====================")
}


// Save original file list
func (stat *ScanStatus) SaveOriginalFileList() {

  if len(stat.OrigFiles) == 0 { return }

  log.Println("Save original file list...")

  outputFile, err := os.OpenFile(OutputFileName,
                                 os.O_CREATE | os.O_TRUNC | os.O_RDWR,
                                 0666)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }

  defer outputFile.Close()

  for key, files := range stat.OrigFiles {

    s := fmt.Sprintf("%08X %08X\n", key.Key1Pos, key.Key2Pos)
    outputFile.WriteString(s)

    for i := range files {
      s := fmt.Sprintf("%x\t%s\n", files[i].Hash, files[i].Path)
      outputFile.WriteString(s)
    }
  }
}


// Export encrypted file list
func (stat *ScanStatus) ExportEncFileList() {

  if len(stat.OrigFiles) == 0 { return }

  log.Println("Export required encrypted file list...")

  f, err := os.Open(InputFileName)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }
  defer f.Close()

  encFileNames := make(map[string]struct{})

  reader := bufio.NewReader(f)

  for {

    line, _, err := reader.ReadLine()
    if err != nil {
      if err == io.EOF {
        err = nil
      }
      break
    }

    // Parse encrypted file info
    entry, encFilePath, err := ParseEncFileEntry(string(line))
    if err != nil {
      log.Printf("Error: Failed to parse encrypted file info (%s)",
                 err.Error())
      continue
    }

    for _, files := range stat.OrigFiles {
      for i := range files {
        if bytes.Equal(entry.Hash, files[i].Hash) {
          encFileNames[encFilePath] = struct{}{}
        }
      }
    }
  }

  outputFile, err := os.OpenFile(OutputFileName2,
                                 os.O_CREATE | os.O_APPEND | os.O_RDWR,
                                 0666)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }
  defer outputFile.Close()

  for filePath := range encFileNames {
    outputFile.WriteString(filePath + string('\n'))
  }
}


// Copy original files
func (stat *ScanStatus) CopyOriginalFiles() {

  log.Println("Copy files...")

  if len(stat.OrigFiles) == 0 { return }

  workDir, err := os.Getwd()
  if err != nil {
    log.Fatal("Error: ", err.Error())
  }

  dirPath := filepath.Join(workDir, OrigFileDirName)

  err = os.MkdirAll(dirPath, 0700)
  if err != nil {
    log.Println("Error:", err.Error())
    stat.NumErrors++
    return
  }

  for _, files := range stat.OrigFiles {

    for i := range files {

      // Copy file
      newFilePath := filepath.Join(dirPath, fmt.Sprintf("%x", files[i].Hash))
      err = CopyFile(files[i].Path, newFilePath)
      if err != nil {

        log.Println("Error:", err.Error())
        stat.NumErrors++

      } else {

        stat.NumCopied++
      }
    }
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

    stat.Lock()
    stat.NumFiles++
    stat.Unlock()

    // Get Hive hash
    hash, err := hive.GetHiveHash(fileName, false)
    if err != nil {
      if err != hive.ErrNoOriginalFileData {
        // Log error
        LogError(err, stat)
      }
      continue
    }

    // Find encrypted file list entry by hash
    i := FindEncFileEntryByHash(ctx.EncFiles, hash, 0)
    if i < 0 {
      continue
    }

    log.Println(fileName)

    stat.Lock()
    stat.NumOriginals++
    stat.Unlock()

    for i >= 0 {
      // Add original file for the specifed key
      stat.AddOrigFile(ctx.EncFiles[i].Key1Pos, ctx.EncFiles[i].Key2Pos,
                       fileName, hash)

      i = FindEncFileEntryByHash(ctx.EncFiles, hash, i + 1)
    }
  } 
}


// Add original file for the specifed key
func (stat *ScanStatus) AddOrigFile(key1Pos, key2Pos uint32,
                                    filePath string, hash []byte) {

  fileInfo, err := os.Stat(filePath)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }

  fileSize := fileInfo.Size()
  key := XORKeyID{key1Pos, key2Pos}
  fileEntry := OrigFileEntry{filePath, fileSize, hash}

  stat.Lock()
  defer stat.Unlock()

  fileList := stat.OrigFiles[key]

  for i := range fileList {
    if bytes.Equal(hash, fileList[i].Hash) { return }
  }

  if len(fileList) < MaxOrigFilesPerKey {

    stat.OrigFiles[key] = append(fileList, fileEntry)

  } else {

    minIdx := 0
    minSize := fileList[0].Size

    for i := range fileList {
      if fileList[i].Size < minSize {
        minIdx = i
        minSize = fileList[i].Size
      }
    }

    if fileSize > minSize {
      fileList[minIdx] = fileEntry
      stat.OrigFiles[key] = fileList
    }
  }
}


// Find encrypted file list entry by hash
func FindEncFileEntryByHash(list []EncFileEntry, hash []byte,
                            startIndex int) int {

  for i := range list {
    if i < startIndex {
      continue
    }
    if bytes.Equal(list[i].Hash, hash) { return i }
  }
  return -1
}


// Copy file
func CopyFile(fileName, newFileName string) (err error) {

  file, err := os.Open(fileName)
  if err != nil { return err }
  defer file.Close()
 
  // Create new file
  newFile, err := os.Create(newFileName)
  if err != nil { return err }
  defer newFile.Close()
 
  _, err = io.Copy(newFile, file)

  return err
}
