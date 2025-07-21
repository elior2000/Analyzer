# Windows Forensics: Analyzer

**Author:** Elior Salimi  
**Class Code:** NX212

---

## Overview

`Windows Forensics: Analyzer` is an automated Bash script designed for rapid forensic analysis of Windows memory and disk images. The script integrates leading forensic tools to extract sensitive information, detect network captures, analyze memory with Volatility, and generate a structured summary report — all in a single automated flow.

- **Supported input:** Memory images (e.g., `.mem`, `.raw`, `.bin`, `.dmp`, `.vmem`, etc.) and disk images (e.g., `.img`, `.dd`, etc.)
- **Forensic tools used:**  
  [Bulk Extractor](https://www.kali.org/tools/bulk-extractor/)  
  [Binwalk](https://www.kali.org/tools/binwalk/)  
  [Foremost](https://www.kali.org/tools/foremost/)  
  [Strings (Sysinternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)  
  [Volatility](https://www.volatilityfoundation.org/releases)

## Features

- **Auto-installation**: Checks and installs all required forensic tools if missing.
- **Works with both disk and memory images**.
- **Memory analysis with Volatility**, including dynamic profile selection (imageinfo).
- **Automated extraction**: Runs all carvers and string searchers.
- **Network capture detection**: Finds and reports `.pcap` or `.pcapng` files found in carved data.
- **Auto-generated forensic report**: Summarizes findings, artifacts, interesting strings (like passwords, tokens), and statistics.
- **ZIP packaging**: Archives all output (report and extracted files) for submission.
- **ANSI colored output** for readability.
- **Extensive comments** for clarity and learning.

## How to Use

```bash
# 1. Make the script executable
chmod +x Analyzer.sh

# 2. Run as root (required for certain forensic tools)
sudo ./Analyzer.sh

# 3. Enter the full path to the image file when prompted
```

> The script will automatically check and prompt to install any missing tool.  
> All analysis outputs will be saved under a timestamped directory and zipped for easy submission or review.

## Example Output

```plaintext
[+] bulk-extractor is already installed.
[+] binwalk is already installed.
[+] foremost is already installed.
[+] strings is already installed.
[+] Volatility is already installed.

Enter the full path to the file you want to analyze: /home/user/evidence/MEMORY.DMP
[+] Memory image detected. Volatility will be used.
[*] Running bulk-extractor...
[*] Running binwalk...
[*] Running foremost...
[*] Running strings...
[*] Identifying possible profiles...
Available profiles:
  [1] Win7SP1x64
  [2] Win7SP0x64
Select a profile number from the list above: 1
[+] Selected profile: Win7SP1x64
[*] Running Volatility analysis (pslist)...
...
[+] Network traffic extracted: Analysis_Output_20250721_120000/foremost/network.pcap (1.2M)

[+] All outputs are saved in: Analysis_Output_20250721_120000
[+] Forensics_Report.log created in Analysis_Output_20250721_120000
[*] Analysis time: 2025-07-21 12:00:00
[*] Total files extracted: 72
[+] All extracted files and the report have been zipped to: Analysis_Output_20250721_120000.zip
```

## Project Structure

- `Analyzer.sh` — main script (run this)
- `Analysis_Output_YYYYMMDD_HHMMSS/` — output directory (auto-created for each analysis)
    - `Forensics_Report.log` — summary report
    - All artifacts, strings, carver outputs, etc.
- `Analysis_Output_YYYYMMDD_HHMMSS.zip` — zipped archive for easy submission

## Submission Guidelines

- Submit both the `.sh` script and the output `.pdf` report (screenshots or summary of your analysis).
- Name your files according to the instructions: `UNIT.STUDENT.PROGRAM.sh` (e.g., `NX212.elior.analyzer.sh`)
- Do **not** share or copy other students' work.
- Add credits/links if you use code from other sources (see below).

## Credits

- This script uses open-source tools: bulk-extractor, binwalk, foremost, strings, and Volatility.
- [Kali Linux tools documentation](https://www.kali.org/tools/)
- [Volatility Foundation](https://www.volatilityfoundation.org/)
- Project guidance: ThinkCyber Group, NX212

## License

For educational use only.  
(c) 2025 Elior Salimi.

---

*See [project documentation PDF](./Windows%20Forensics.pdf) for full instructions and sample results.*
