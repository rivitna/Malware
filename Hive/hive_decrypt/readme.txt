1. Scan encrypted files.
Need to run on attacked host.

Usage:
1_scan_encr64.exe ransom_ext [path1] [path2] ... [pathN]

Example:
Scan encrypted files *.*.p5rwm on all fixed drives:
1_scan_encr64.exe p5rwm

Input files:
-

Output files:
.\<COMP_NAME>_encr.log - log
.\encrypted.txt - encrypted file hash list


2. Extract original files.
Need to run on a host that has unencrypted files that could be on the attacked host.

Usage:
2_scan_orig64.exe [path1] [path2] ... [pathN]

Example:
Scan all fixed drives on host:
2_scan_orig64.exe

Input files:
.\encrypted.txt

Output files:
.\<COMP_NAME>_orig.log - log
.\original.txt - original file hash list
.\need_encr.txt - necessary encrypted file list
.\original\ - directory with extracted original files


3. Extract encrypted files.
Need to run again on attacked host.

Usage:
3_collect_encr64.exe

Input files:
.\need_encr.txt

Output files:
.\<COMP_NAME>_encr2.log - log
.\encrypted\ - directory with extracted encrypted files


4. Extract encryption keys.

Usage:
4_extract_keys64.exe

Input files:
.\original\ - directory with extracted original files
.\encrypted\ - directory with extracted encrypted files

Output files:
.\keys.log - log
.\keys\ - directory with extracted encryption keys

5. Decrypt files

Usage:
decryptor.exe [-d] [-x] ransom_ext [path1] [path2] ... [pathN]
-d - delete encrypted files
-x - extended log (decrypted file list)

Input files:
.\keys\ - directory with extracted encryption keys

Output files:
.\.log - log
.\<COMP_NAME>_<DATE_TIME>.log
