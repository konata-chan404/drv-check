# drv-check
drv-check is a simple yet robust command-line tool for security research targeting Windows drivers, designed to report automate reports on driver's modules and imports.

Usage
-----
To use drv-check, run the compiled binary in the command-line, passing the path to the driver file or directory you want to analyze. The tool will provide detailed reports for each driver found in the specified directory.
```
USAGE:
    drv-check [OPTIONS] <path>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --imports <imports>    Path to a JSON file containing the import set (optional)

ARGS:
    <path>    The path to the driver file or directory to analyze
```

Example
----
Analyze a single driver file:
```
drv-check C:\path\to\driver.sys
```
Analyze all drivers in a directory:
```
drv-check C:\path\to\drivers\directory
```
Analyze a directory with a custom import set:
```
drv-check -i custom_imports.json C:\path\to\drivers\directory
```
Report Format
-------------

The drv-check tool generates a JSON-formatted report for each analyzed driver. The report includes details such as the driver name, hash, found imports, and matching imports based on the provided import set.
```json
[
  {
    "name": "C:\\Users\\Yael\\drvcheck\\7475bfea6ea1cd54029208ed59b96c6b.sys",
    "hash": "2b120de80a5462f8395cfb7153c86dfd44f29f0776ea156ec4a34fa64e5c4797",
    "found_imports": [
      {
        "va": "0x0000000000017134",
        "hint": 1230,
        "name": "MmGetSystemRoutineAddress"
      },
      {
        "va": "0x0000000000017150",
        "hint": 2527,
        "name": "__C_specific_handler"
      },
      {
        "va": "0x0000000000017168",
        "hint": 2528,
        "name": "__chkstk"
      },
      {
        "va": "0x0000000000017174",
        "hint": 1250,
        "name": "MmMapLockedPagesSpecifyCache"
      },
      {
        "va": "0x0000000000017194",
        "hint": 929,
        "name": "KeBugCheckEx"
      }
    ],
    "matching_imports": [
      {
        "va": "0x0000000000017174",
        "hint": 1250,
        "name": "MmMapLockedPagesSpecifyCache"
      }
    ]
  }
  ...
]
```
