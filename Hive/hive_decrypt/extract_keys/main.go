package main


import (
  "os"
  "io"
  "log"
  "fmt"
  "time"
  "bytes"
  "path/filepath"

  "hive_decrypt/hive"
)


// Encrypted file directory name
const EncFileDirName string = "encrypted"
// Original file directory name
const OrigFileDirName string = "original"
// Key directory name
const KeyDirName string = "keys"
// Log file name
const LogName string = "keys.log"


// ScanContext structure
type ScanContext struct {
  EncFileDirPath   string
  OrigFileDirPath  string
  KeyDirPath       string
  Keys             []hive.XORKey
}


// Main
func main() {

  t1 := time.Now()

  log.SetFlags(0)

  logFile, err := os.OpenFile(LogName, os.O_CREATE | os.O_TRUNC | os.O_RDWR,
                              0666)
  if err != nil {

    fmt.Println("Error:", err.Error())

    log.SetOutput(os.Stdout)

  } else {

    defer logFile.Close()

    mw := io.MultiWriter(os.Stdout, logFile)
    log.SetOutput(mw)
  }

  workDir, err := os.Getwd()
  if err != nil {
    log.Fatal("Error: ", err.Error())
  }

  encFileDirPath := filepath.Join(workDir, EncFileDirName)
  isExists, err := IsDirectoryExist(encFileDirPath)
  if err != nil {
    log.Fatal("Error: ", err.Error())
  }
  if !isExists {
    log.Fatalf("Error: Directory \"%s\" does not exist", encFileDirPath)
  }

  origFileDirPath := filepath.Join(workDir, OrigFileDirName)
  isExists, err = IsDirectoryExist(origFileDirPath)
  if err != nil {
    log.Fatal("Error: ", err.Error())
  }
  if !isExists {
    log.Fatalf("Error: Directory \"%s\" does not exist", origFileDirPath)
  }

  ctx := new(ScanContext)
  ctx.EncFileDirPath = encFileDirPath
  ctx.OrigFileDirPath = origFileDirPath
  ctx.KeyDirPath = filepath.Join(workDir, KeyDirName)

  // Extract XOR keys
  ctx.ExtractXORKeys()

  // Save XOR keys
  ctx.SaveXORKeys()

  t2 := time.Now()
  elapsed := t2.Sub(t1)

  log.Println()
  log.Println("Elapsed:", elapsed)
}


// Extract XOR keys
func (ctx *ScanContext) ExtractXORKeys() {

  f, err := os.Open(ctx.EncFileDirPath)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }
  defer f.Close()

  fileList, err := f.ReadDir(-1)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }

  log.Println("Scan encrypted files...")

  for _, file := range fileList {

    if file.IsDir() {
      continue
    }

    // Extract XOR key
    encFilePath := filepath.Join(ctx.EncFileDirPath, file.Name())
    ctx.ExtractXORKey(encFilePath)

    log.Println()
  }
}


// Extract XOR key
func (ctx *ScanContext) ExtractXORKey(encFilePath string) {

  log.Println("File name:     ", filepath.Base(encFilePath))

  // Analyze encrypted file
  encFileInfo, err := hive.AnalyzeEncFile(encFilePath)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }

  key1Pos := hive.GetKey1Pos(encFileInfo.N1)
  key2Pos := hive.GetKey2Pos(encFileInfo.N2)

  log.Printf("Key table hash: %x", encFileInfo.KeyTabHash)
  log.Printf("Key:            %08X %08X", key1Pos, key2Pos)
  log.Printf("Key size:       %d", encFileInfo.NumBlocks * hive.BlockSize)

  var hash, hash1, origHash []byte

  // Get Hive hash
  hash1, err = hive.GetHiveHash(encFilePath, false)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }

  log.Printf("Hive hash #1:   %x", hash1)

  if key1Pos == key2Pos {

    // Get Hive hash
    hash, err = hive.GetHiveHash(encFilePath, true)
    if err != nil {
      log.Println("Error:", err.Error())
      return
    }

    log.Printf("Hive hash #2:   %x", hash)

  } else {

    hash = hash1

  }

  origFilePath := filepath.Join(ctx.OrigFileDirPath, fmt.Sprintf("%x", hash1))

  // Get original file Hive hash
  origHash, err = hive.GetHiveHash(origFilePath, key1Pos == key2Pos)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }

  if !bytes.Equal(hash, origHash) {
    log.Println("Error:", "Hive hashes mismatch")
    return
  }

  // Extract XOR key from encrypted and original file
  key, err := hive.ExtractXORKey(encFilePath, origFilePath)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }

  // Add XOR key
  ctx.AddXORKey(key)
}


// Add XOR key
func (ctx *ScanContext) AddXORKey(key *hive.XORKey) {

  if len(key.Data) == 0 { return }

  for i := range ctx.Keys {

    if (key.Key1Pos == ctx.Keys[i].Key1Pos) &&
       (key.Key2Pos == ctx.Keys[i].Key2Pos) &&
       bytes.Equal(key.KeyTabHash, ctx.Keys[i].KeyTabHash) {

      minLen := len(ctx.Keys[i].Data)
      if len(key.Data) < minLen {
        minLen = len(key.Data)
      }

      if !bytes.Equal(ctx.Keys[i].Data[:minLen], key.Data[:minLen]) {
        log.Printf("Error: Key data does match (%08X %08X, %d)",
                   ctx.Keys[i].Key1Pos, ctx.Keys[i].Key2Pos, minLen)
      }

      if len(key.Data) > len(ctx.Keys[i].Data) {
        ctx.Keys[i] = *key
      }
      return
    }
  }

  ctx.Keys = append(ctx.Keys, *key)
}


// Save XOR keys
func (ctx *ScanContext) SaveXORKeys() {

  log.Println("Save encryption keys...")

  err := os.MkdirAll(ctx.KeyDirPath, 0700)
  if err != nil {
    log.Println("Error:", err.Error())
    return
  }

  numSaved := 0

  for i := range ctx.Keys {
    // Save XOR key
    if ctx.SaveXORKey(&ctx.Keys[i]) {
      numSaved++
    }
  }

  log.Printf("Extracted keys: %d", numSaved)
}


// Save XOR key
func (ctx *ScanContext) SaveXORKey(key *hive.XORKey) bool {

  // Make key table hash part
  keyTableHashExtPart := hive.MakeKeyTableHashExtPart(key.KeyTabHash)

  keyFileName := fmt.Sprintf("%s%08X_%08X",
                             keyTableHashExtPart, key.Key1Pos, key.Key2Pos)
  keyFilePath := filepath.Join(ctx.KeyDirPath, keyFileName)

  // Write data to file
  err := WriteDataToFile(keyFilePath, key.Data)
  if err != nil {
    log.Println("Error:", err.Error())
    return false
  }

  log.Printf("Key %s (%d bytes) saved", keyFileName, len(key.Data))
  return true
}


// Write data to file
func WriteDataToFile(fileName string, data []byte) (err error) {

  f, err := os.Create(fileName)
  if err != nil { return err }
  defer f.Close()

  _, err = f.Write(data)
  if err != nil { return err }

  return nil
}


// Check if the specified directory exists
func IsDirectoryExist(dirPath string) (isExists bool, err error) {

  fileInfo, err := os.Stat(dirPath)
  if (err == nil) && fileInfo.IsDir() { return true, nil }
  if os.IsNotExist(err) { return false, nil }
  return false, err
}
