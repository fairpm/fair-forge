# Sentinel Shell Scripts

Sentinel scripts are part of the FAIR Forge Toolchain, and act as an early detection system for checking received packages. Sentinel will flag anomalies that need closer inspection or present critical issues.

## 1. Sentinel Write Check

Starting from a given target directory, `sentinel-write-check.sh` will recursively check files and directories for anything with world-writeable permissions; i.e., "write" permissions are enabled in the final position of the octal file permissions. An optional flag will unset this, reducing the octal number by two, so `662` becomes `660`, `757` becomes `755`, and so on.

The script should work in most modern shells, and is hardened against some basic attacks. For example, it will not `chmod` a symlink that could point `/somewhere-vital/`. The script's output should not reveal anything about the current environment, so does not output an absolute path, only the relative path from the stated target directory.

### Usage

`./sentinel-write-check.sh targetdir`

Optional: remove the offending world-writeable setting with the `--fix` flag.


### Explanation

In Unix/Linux systems, octal file permissions are numerical representations of file permissions, and are a clever bulletproof way of turning 9 letters into three digits, elegantly storing them in only 9 bits. For the record, nine literal letters (`rwxrwxrwx`) in ASCII would use 72 bits. Unix is old enough that those bit mattered. Learn how it works at https://www.redhat.com/en/blog/linux-file-permissions-explained and https://linuxvox.com/blog/linux-octal-permissions/ or just skip to https://chmod-calculator.com/ if you must.

## 2. Sentinel File Stats

The file stats script gathers a quick statistical overview of what's in a directory. After scanning, it will report the number of files, number of lines, and file size for each file type, such as `.php`, `.js`, image types, and project documentation (`.txt` or `.md`).

 While scanning, the script will specifically check for indicators of common external sources for updates, such as `.gitignore` file. In additon to Git, Composer, Node.js, and PyPI sources are flagged. These may not be important, but may indicate either that the package is installing software from external sources or that the package wasn't cleaned up before being distributed.

The script will also check for three specific files, `readme`, `security`, and `license`, which should be included as `.md` or `.txt` files as a matter of best practice. If present but with an improbably-small file size, it'll flag that too. (A `touch` is not enough for a best-practice indicator.)


### Usage

`./sentinel-file-stats targetdir`

Optional flags:

`-s` silent, no output to terminal
`-j` write results to a `.json` file


## 3. Sentinel File Integrity

The file integrity script will recursively scan a target directory, doing a deeper check for anomalies embedded in the file structure. It will report any mime-type mistmatches encountered, such as a file named `file.jpg` with a mime-type suggesting it may contain executable code. It will check for and count binary files or archives, hidden directories, SUID/SGID files, and other basic spoofing attempts like double-extension file names. (This will yield false positives, but names like `file.txt.exe` likely indicate something malicious. For good measure, it'll also check if there's any \__MACOS cruft left behind.

This script is more resource-intense than the first two, as it does a deeper inspection of each file.

### Usage

`./sentinel-integrity.sh targetdir`

Optional flags:

`-s` silent, no output to terminal
`-j` write results to a `.json` file



## License: MIT


