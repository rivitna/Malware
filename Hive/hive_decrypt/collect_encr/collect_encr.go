package main


import (
  "os"
  "io"
  "log"
  "fmt"
  "time"
  "bufio"
  "strings"
  "path/filepath"
)


// Intput file name
const InputFileName string = "need_encr.txt"
// Destination directory name
const DestDirName string = "encrypted"
// Log file name
const LogName string = "encr2.log"


// AppStatus structure
type AppStatus struct {
  NumFiles   uint
  NumCopied  uint
  NumErrors  uint
}


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

  // Import file list
  files, err := ImportFileList()
  if err != nil {
    log.Fatal("Error: ", err.Error())
  }
  numFiles := len(files)
  if numFiles == 0 {
    log.Fatal("File list is empty")
  }

  stat := new(AppStatus)

  // Copy files
  stat.CopyFiles(files)

  log.Printf("==================")
  log.Printf("Files:  %10d", stat.NumFiles)
  log.Printf("Copied: %10d", stat.NumCopied)
  log.Printf("Errors: %10d", stat.NumErrors)
  log.Printf("==================")

  t2 := time.Now()
  elapsed := t2.Sub(t1)

  log.Println("Elapsed:", elapsed)
}


// Import file list
func ImportFileList() (list []string, err error) {

  log.Println("Import file list...")

  f, err := os.Open(InputFileName)
  if err != nil { return nil, err }
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

    filePath := strings.TrimSpace(string(line))
    encFileNames[filePath] = struct{}{}
  }

  for filePath := range encFileNames {
    list = append(list, filePath)
  }

  return list, err
}


// Copy files
func (stat *AppStatus) CopyFiles(files []string) {

  log.Println("Copy files...")

  if len(files) == 0 { return }

  workDir, err := os.Getwd()
  if err != nil {
    log.Fatal("Error: ", err.Error())
  }

  dirPath := filepath.Join(workDir, DestDirName)

  err = os.MkdirAll(dirPath, 0700)
  if err != nil {
    log.Println("Error:", err.Error())
    stat.NumErrors++
    return
  }

  for i := range files {

    stat.NumFiles++

    log.Println(files[i])

    // Copy file
    fileName := filepath.Base(files[i])
    newFilePath := filepath.Join(dirPath, fileName)
    err = CopyFile(files[i], newFilePath)
    if err != nil {

      log.Println("Error:", err.Error())
      stat.NumErrors++

    } else {

      stat.NumCopied++
    }
  }
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
