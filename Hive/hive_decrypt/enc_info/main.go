package main


import (
  "os"
  "fmt"
  "path/filepath"

  "hive_decrypt/hive"
)


// Main
func main() {

  if (len(os.Args) < 2) {
    fmt.Println("Usage: " + filepath.Base(os.Args[0]) + " filename")
    os.Exit(0)
  }

  filePath := os.Args[1]

  // Analyze file
  AnalyzeFile(filePath)
}


// Analyze file
func AnalyzeFile(filePath string) {

  // Analyze exported key file name
  keyTabHash, err := hive.AnalyzeExportedKeyFilename(filePath)
  if (err == nil) {
    fmt.Println("Type:               ", "Exported key table")
    fmt.Println("Ransom extension:   ", hive.GetRansomExt(filePath))
    fmt.Printf("Key table hash:      %x\n", keyTabHash)
    return
  }

  // Analyze encrypted file
  AnalyzeEncFile(filePath)

  // Get Hive hash 1
  hash, err := hive.GetHiveHash(filePath, false)
  if err != nil {
    fmt.Println("Error:", err.Error())
  } else {
    fmt.Printf("Hive hash #1:        %x\n", hash)
  }

  // Get Hive hash 2
  hash, err = hive.GetHiveHash(filePath, true)
  if err != nil {
    fmt.Println("Error:", err.Error())
  } else {
    fmt.Printf("Hive hash #2:        %x\n", hash)
  }
}


// Analyze encrypted file
func AnalyzeEncFile(filePath string) {

  // Analyze encrypted file
  encFileInfo, err := hive.AnalyzeEncFile(filePath)
  if err != nil {
    if err != hive.ErrInvalidEncFileName {
      fmt.Println("Error:", err.Error())
    }
    return
  }

  fileName := filepath.Base(filePath)
  encDataSize := encFileInfo.NumBlocks * hive.BlockSize
  if (int64(encDataSize) > encFileInfo.FileSize) {
    encDataSize = uint32(encFileInfo.FileSize)
  }

  fmt.Println("Type:               ", "Encrypted file")
  fmt.Println("Encrypted file name:", fileName)
  fmt.Println("Original file name: ", hive.GetOriginalFileName(fileName))
  fmt.Println("Ransom extension:   ", hive.GetRansomExt(fileName))
  fmt.Printf("Key table hash:      %x\n", encFileInfo.KeyTabHash)
  fmt.Printf("n1:                  %x\n", encFileInfo.N1)
  fmt.Printf("n2:                  %x\n", encFileInfo.N2)
  fmt.Printf("Key1 pos:            %x\n", hive.GetKey1Pos(encFileInfo.N1))
  fmt.Printf("Key1 size:           %d\n", hive.Key1Size)
  fmt.Printf("Key2 pos:            %x\n", hive.GetKey2Pos(encFileInfo.N2))
  fmt.Printf("Key2 size:           %d\n", hive.Key2Size)
  fmt.Printf("File size:           %d\n", encFileInfo.FileSize)
  fmt.Printf("Block size:          %d\n", hive.BlockSize)
  fmt.Printf("Number of blocks:    %d\n", encFileInfo.NumBlocks)
  fmt.Printf("Encrypted data size: %d\n", encDataSize)
  fmt.Printf("Block space:         %d\n", encFileInfo.BlockSpace)
}
