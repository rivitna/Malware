package hive


import (
  "os"
  "io"
  "bufio"
  "errors"
  "path/filepath"
  "encoding/base64"
  "strings"
  "strconv"
  "crypto/sha256"
)


// Ransom extension separator
const RansomExtSeparator = '.'
// Key extension
const KeyExt = "key"
// Ransom extension length
const RansomExtLen = 5
// Key table hash part length
const KeyTableHashExtPartLen = 44
// Key ID extension part length
const KeyIDExtPartLen = 12
// Metadata extension length
const MetadataExtLen = KeyTableHashExtPartLen + KeyIDExtPartLen
// Exported key file name length
const KeyFileNameLen = 2 + KeyTableHashExtPartLen + len(KeyExt) +
                       RansomExtLen
// Encrypted file extension length
const EncFileExtLen = 2 + RansomExtLen + MetadataExtLen


// Key table size
const EncKeyTabSize = 0x300000
// Key table hash size
const EncKeyTabHashSize = 32

// Max number of blocks
const MaxNumBlocks = 256
// Block size
const BlockSize = 4096

// Key1 size
const Key1Size = 0x100000
// Key2 size
const Key2Size = 0xC00


// Errors
// Invalid XOR key file name error
var ErrInvalidXORKeyFileName = errors.New("Invalid XOR key file name")
// Invalid exported key file name error
var ErrInvalidKeyFileName = errors.New("Invalid key file name")
// Invalid Hive encrypted file name error
var ErrInvalidEncFileName = errors.New("Invalid encrypted file name")
// Original file mismatch error
var ErrOriginalFileMismatch = errors.New("Original file mismatch")
// Key mismatch error
var ErrKeyMismatch = errors.New("Key mismatch")
// Key size is not sufficient
var ErrInsufficientKeySize = errors.New("Key size is not sufficient")
// No original file data error
var ErrNoOriginalFileData = errors.New("No original file data")


// Hive encrypted file info
type EncryptedFileInfo struct {
  KeyTabHash  []byte
  N1          uint32
  N2          uint32
  FileSize    int64
  NumBlocks   uint32
  BlockSpace  int64
}


// XOR Key info
type XORKey struct {
  KeyTabHash  []byte
  Key1Pos     uint32
  Key2Pos     uint32
  Data        []byte
}


// Get Key1 position
func GetKey1Pos(n1 uint32) uint32 { return n1 % (EncKeyTabSize - Key1Size) }


// Get Key2 position
func GetKey2Pos(n2 uint32) uint32 { return n2 % (EncKeyTabSize - Key2Size) }


// Get key table hash part
func GetKeyTableHashExtPart(encFileName string) string {
  pos := len(encFileName) - (EncFileExtLen - 1)
  return encFileName[pos : pos + KeyTableHashExtPartLen]
}


// Get key ID extension part
func GetKeyIDExtPart(encFileName string) string {
  pos := len(encFileName) - (EncFileExtLen - KeyTableHashExtPartLen - 1)
  return encFileName[pos : pos + KeyIDExtPartLen]
}


// Get original file name
func GetOriginalFileName(encFileName string) string {
  return encFileName[:len(encFileName) - EncFileExtLen]
}


// Get ransom extension
func GetRansomExt(encFileName string) string {
  return encFileName[len(encFileName) - RansomExtLen:]
}


// Make key table hash part
func MakeKeyTableHashExtPart(keyTabHash []byte) string {
  var data [33]byte
  copy(data[:32], keyTabHash)
  data[32] = 0xFF
  return base64.URLEncoding.EncodeToString(data[:])
}


// Load XOR key from file
func LoadXORKey(filePath string) (key *XORKey, err error) {

  fileName := filepath.Base(filePath)

  if len(fileName) <= KeyTableHashExtPartLen {
    return nil, ErrInvalidXORKeyFileName
  }

  keyTableHashExtPart := fileName[:KeyTableHashExtPartLen]

  keyTabHash, err := base64.URLEncoding.DecodeString(keyTableHashExtPart)
  if (err != nil) || (keyTabHash[32] != 0xFF) {
    return nil, ErrInvalidXORKeyFileName
  }

  strList := strings.SplitN(fileName[KeyTableHashExtPartLen:], "_", 2)

  var k [2]uint64

  for i := 0; i < 2; i++ {
    k[i], err = strconv.ParseUint(strList[i], 16, 32)
    if err != nil { return nil, ErrInvalidXORKeyFileName }
  }

  if (k[0] >= (EncKeyTabSize - Key1Size)) ||
     (k[1] >= (EncKeyTabSize - Key2Size)) {
    return nil, ErrInvalidXORKeyFileName
  }

  f, err := os.Open(filePath)
  if err != nil { return nil, err }
  defer f.Close()

  fileInfo, err := f.Stat()
  if err != nil { return nil, err }

  fileSize := fileInfo.Size()
  keyData := make([]byte, fileSize)

  buf := bufio.NewReader(f)
  bytesRead, err := buf.Read(keyData)
  if err != nil { return nil, err }

  key = &XORKey{keyTabHash[:32], uint32(k[0]), uint32(k[1]),
                keyData[:bytesRead]}

  return key, nil
}


// Analyze exported key file name
func AnalyzeExportedKeyFilename(filePath string) (hash []byte, err error) {

  fileName := filepath.Base(filePath)

  fileNameLen := len(fileName)

  if (fileNameLen != KeyFileNameLen) { return nil, ErrInvalidKeyFileName }

  ransomExtPos := fileNameLen - RansomExtLen
  keyExtPos := ransomExtPos - (1 + len(KeyExt))

  if (fileName[ransomExtPos - 1] != RansomExtSeparator) ||
     (fileName[keyExtPos - 1] != RansomExtSeparator) ||
     (fileName[keyExtPos : ransomExtPos - 1] != KeyExt) {
    return nil, ErrInvalidKeyFileName
  }

  keyTableHashExtPart := fileName[:keyExtPos - 1]

  keyTabHash, err := base64.URLEncoding.DecodeString(keyTableHashExtPart)
  if (err != nil) || (keyTabHash[32] != 0xFF) {
    return nil, ErrInvalidKeyFileName
  }

  return keyTabHash[:32], nil
}


// Analyze encrypted file name
func (info *EncryptedFileInfo) AnalyzeEncFilename(filePath string) (err error) {

  fileName := filepath.Base(filePath)

  fileNameLen := len(fileName)

  if (fileNameLen < EncFileExtLen) { return ErrInvalidEncFileName }

  ransomExtPos := fileNameLen - RansomExtLen
  encFileExtPos := ransomExtPos - (1 + MetadataExtLen)

  if (fileName[ransomExtPos - 1] != RansomExtSeparator) ||
     (fileName[encFileExtPos - 1] != RansomExtSeparator) {
    return ErrInvalidEncFileName
  }

  metadataExt := fileName[encFileExtPos : ransomExtPos - 1]

  metadata, err := base64.URLEncoding.DecodeString(metadataExt)
  if err != nil { return ErrInvalidEncFileName }

  info.KeyTabHash = metadata[:32]

  if (metadata[32] != 0xFF) || (metadata[41] != 0x34) {
    return ErrInvalidEncFileName
  }

  info.N1 = uint32(metadata[33]) |
            (uint32(metadata[34]) << 8) |
            (uint32(metadata[35]) << 16) |
            (uint32(metadata[36]) << 24)

  info.N2 = uint32(metadata[37]) |
            (uint32(metadata[38]) << 8) |
            (uint32(metadata[39]) << 16) |
            (uint32(metadata[40]) << 24)

  return nil
}


// Adjust file size
func (info *EncryptedFileInfo) AdjustFileSize(fileSize int64) {

  info.FileSize = fileSize

  if fileSize == 0 {
    info.NumBlocks = 0
    info.BlockSpace = 0
    return
  }

  numBlocks := uint32(30 * (fileSize / BlockSize) / 100)

  if fileSize <= BlockSize {
    numBlocks = 1
  } else if (numBlocks < 2) {
    numBlocks = 2
  } else {
    if (numBlocks > MaxNumBlocks) {
      numBlocks = MaxNumBlocks
    }
  }

  info.NumBlocks = numBlocks

  if numBlocks > 1 {
    info.BlockSpace = (fileSize - int64(numBlocks * BlockSize)) /
                      int64(numBlocks - 1)
  }
}


// Analyze encrypted file
func AnalyzeEncFile(filePath string) (info *EncryptedFileInfo, err error) {

  info = new(EncryptedFileInfo)

  // Analyze encrypted file name
  err = info.AnalyzeEncFilename(filePath)
  if err != nil { return info, err }

  fileInfo, err := os.Stat(filePath)
  if err != nil { return info, err }

  // Adjust file size
  info.AdjustFileSize(fileInfo.Size())

  return info, nil
}


// Extract XOR key from encrypted and original file
func ExtractXORKey(encFilePath, origFilePath string) (key *XORKey,
                                                      err error) {

  var info EncryptedFileInfo

  // Analyze encrypted file name
  err = info.AnalyzeEncFilename(encFilePath)
  if err != nil { return nil, err }

  // Open encrypted file
  f1, err := os.OpenFile(encFilePath, os.O_RDONLY, 0)
  if err != nil { return nil, err }

  defer f1.Close()

  // Open original file
  f2, err := os.OpenFile(origFilePath, os.O_RDONLY, 0)
  if err != nil { return nil, err }

  defer f2.Close()

  fileInfo1, err := f1.Stat()
  if err != nil { return nil, err }

  fileInfo2, err := f2.Stat()
  if err != nil { return nil, err }

  fileSize := fileInfo1.Size()
  if fileSize != fileInfo2.Size() { return nil, ErrOriginalFileMismatch }

  // Adjust file size
  info.AdjustFileSize(fileSize)

  var keyData []byte

  var buf1 [BlockSize]byte
  var buf2 [BlockSize]byte

  var fileOff int64

  var blockNum uint32 = 1
  for ; blockNum <= info.NumBlocks; blockNum++ {

    if blockNum == 1 {
      fileOff = 0
    } else if blockNum == info.NumBlocks {
      if fileSize > fileOff + BlockSize {
        fileOff = fileSize - BlockSize
      }
    } else {
      fileOff += info.BlockSpace
    }

    var bytesRead1 int
    var bytesRead2 int

    bytesRead1, err = f1.ReadAt(buf1[:], fileOff)
    if (err != nil) && (err != io.EOF) { return nil, err }

    bytesRead2, err = f2.ReadAt(buf2[:], fileOff)
    if (err != nil) && (err != io.EOF) { return nil, err }

    if (bytesRead1 != bytesRead2) { return nil, ErrOriginalFileMismatch }

    if (bytesRead1 == 0) {
      break
    }

    // Xor blocks
    var i uint32
    for i = 0; i < uint32(bytesRead1); i++ {
      buf1[i] ^= buf2[i]
    }

    keyData = append(keyData, buf1[:bytesRead1]...)

    fileOff += int64(bytesRead1)
  }

  key = &XORKey{info.KeyTabHash, GetKey1Pos(info.N1), GetKey2Pos(info.N2),
                keyData}

  return key, nil
}


// Decrypt file
func DecryptFile(filePath, newFilePath string, removeEncrypted bool,
                 xorKeyData []byte) (err error) {

  // Copy file
  err = CopyFile(filePath, newFilePath)
  if err != nil { return err }

  // Decrypt file
  err = InternalDecryptFile(newFilePath, xorKeyData)
  if err != nil {

    // Delete file
    os.Remove(newFilePath)
    return err

  } else {

    if removeEncrypted {
      // Delete encrypted file
      os.Remove(filePath)
    }
  }

  return nil
}


// Decrypt file
func InternalDecryptFile(filePath string, xorKeyData []byte) (err error) {

  f, err := os.OpenFile(filePath, os.O_RDWR, 0600)
  if err != nil { return err }

  defer f.Close()

  fileInfo, err := f.Stat()
  if err != nil { return err }

  fileSize := fileInfo.Size()

  if fileSize == 0 { return nil }

  numBlocks := uint32(30 * (fileSize / BlockSize) / 100)

  if fileSize <= BlockSize {
    numBlocks = 1
  } else if (numBlocks < 2) {
    numBlocks = 2
  } else {
    if (numBlocks > MaxNumBlocks) {
      numBlocks = MaxNumBlocks
    }
  }

  encDataSize := int(numBlocks * BlockSize)
  if int64(encDataSize) > fileSize {
    encDataSize = int(fileSize)
  }
  if len(xorKeyData) < encDataSize {
    return ErrInsufficientKeySize
  }

  var buf [BlockSize]byte

  var totalPos uint32 = 0

  var blockSpace int64

  if numBlocks > 1 {
    blockSpace = (fileSize - int64(numBlocks * BlockSize)) /
                 int64(numBlocks - 1)
  } else {
    blockSpace = 0
  }

  var fileOff int64

  var blockNum uint32 = 1
  for ; blockNum <= numBlocks; blockNum++ {

    if blockNum == 1 {
      fileOff = 0
    } else if blockNum == numBlocks {
      if fileSize > fileOff + BlockSize {
        fileOff = fileSize - BlockSize
      }
    } else {
      fileOff += blockSpace
    }

    var bytesRead int

    bytesRead, err = f.ReadAt(buf[:], fileOff)
    if (err == io.EOF) { err = nil }
    if (err != nil) || (bytesRead == 0) { return err }

    // Encrypt block
    var i uint32
    for i = 0; i < uint32(bytesRead); i++ {
      buf[i] ^= xorKeyData[totalPos + i]
    }

    _, err = f.WriteAt(buf[:bytesRead], fileOff)
    if err != nil { return err }

    fileOff += int64(bytesRead)
    totalPos += uint32(bytesRead)
  }

  return nil
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


// Get Hive hash
func GetHiveHash(filePath string, keyPosMatch bool) (hash []byte,
                                                     err error) {

  f, err := os.OpenFile(filePath, os.O_RDONLY, 0)
  if err != nil { return nil, err }

  defer f.Close()

  fileInfo, err := f.Stat()
  if err != nil { return nil, err }

  fileSize := fileInfo.Size()

  numBlocks := uint32(30 * (fileSize / BlockSize) / 100)

  if fileSize == 0 { return nil, ErrNoOriginalFileData }

  if fileSize <= BlockSize {
    numBlocks = 1
  } else if (numBlocks < 2) {
    numBlocks = 2
  } else {
    if (numBlocks > MaxNumBlocks) {
      numBlocks = MaxNumBlocks
    }
  }

  var blockSpace int64

  if numBlocks > 1 {
    blockSpace = (fileSize - int64(numBlocks * BlockSize)) /
                 int64(numBlocks - 1)
  } else {
    blockSpace = 0
  }

  if !keyPosMatch && (blockSpace <= 0) {
    return nil, ErrNoOriginalFileData
  }

  var immAreaSize uint32 = 0
  if keyPosMatch {
    immAreaSize = Key2Size
    if immAreaSize > Key1Size {
      immAreaSize = Key1Size
    }
  }

  var bufSize int = 0
  if blockSpace > 0 {
    bufSize = int(blockSpace) + int(numBlocks - 2)
  }
  if bufSize < BlockSize {
    bufSize = BlockSize
  }

  h := sha256.New()

  var zeroBuf [BlockSize]byte

  buf := make([]byte, bufSize)

  var totalPos uint32 = 0

  var fileOff int64 = 0

  var blockNum uint32 = 1
  for {

    var bytesRead int = 0

    if totalPos < immAreaSize {

      bytesToRead := int(immAreaSize - totalPos)
      if bytesToRead > BlockSize {
        bytesToRead = BlockSize
      }

      bytesRead, err = f.ReadAt(buf[:bytesToRead], fileOff)
      if (err != nil) && (err != io.EOF) { return nil, err }

      if (bytesRead == 0) {
        break
      }

      h.Write(buf[:bytesRead])
    }

    if (bytesRead < BlockSize) && (fileOff + int64(bytesRead) < fileSize) {

      bytesToRead := BlockSize - bytesRead
      if int64(bytesToRead) > fileSize - fileOff {
        bytesToRead = int(fileSize - fileOff)
      }
      h.Write(zeroBuf[:bytesToRead])
      bytesRead += bytesToRead
    }

    if blockNum == numBlocks {
      break
    }

    fileOff += int64(bytesRead)
    totalPos += uint32(bytesRead)
    blockNum++

    var spaceSize int
    if blockNum == numBlocks {
      if fileSize <= fileOff + BlockSize {
        continue
      }
      spaceSize = int(fileSize - (fileOff + BlockSize))
    } else {
      spaceSize = int(blockSpace)
    }

    bytesRead, err = f.ReadAt(buf[:spaceSize], fileOff)
    if (err != nil) && (err != io.EOF) { return nil, err }

    if (bytesRead == 0) {
      break
    }

    h.Write(buf[:bytesRead])

    fileOff += int64(bytesRead)
  }

  return h.Sum(nil), nil
}
