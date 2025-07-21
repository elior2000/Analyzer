#!/bin/bash

# =============================================
#   Windows Forensics: Analyzer
#   Student Name: Elior Salimi
#   Class Code: NX212
# =============================================

# Exit if not run as root
if [[ $EUID -ne 0 ]]; then
    echo -e "\033[1;31m[!] Please run this script as root.\033[0m"
    exit 1
fi

# Display ASCII banner using figlet if available
if command -v figlet >/dev/null 2>&1; then
    figlet "Windows Forensics: Analyzer"
else
    echo "==========================================="
    echo "      Windows Forensics: Analyzer"
    echo "==========================================="
fi

# Function to check both 'bulk-extractor' and 'bulk_extractor'
check_bulk_extractor() {
    if command -v bulk-extractor >/dev/null 2>&1 || command -v bulk_extractor >/dev/null 2>&1; then
        echo -e "\033[1;32m[+] bulk-extractor is already installed.\033[0m"
    else
        echo -e "\033[1;31m[!] bulk-extractor is not installed.\033[0m"
        read -p "Do you want to install bulk-extractor? (Y/N): " answer
        case $answer in
            [Yy]* )
                echo -e "\033[1;34mInstalling bulk-extractor...\033[0m"
                sudo apt update
                sudo apt install -y bulk-extractor
                ;;
            * )
                echo -e "\033[1;33mSkipping bulk-extractor installation. This may cause issues later.\033[0m"
                ;;
        esac
    fi
}

# List of standard forensic tools to check (except bulk-extractor)
TOOLS=("binwalk" "foremost" "strings")

# Function to check and offer to install each tool
check_and_install_tools() {
    for TOOL in "${TOOLS[@]}"; do
        if ! command -v "$TOOL" >/dev/null 2>&1; then
            echo -e "\033[1;31m[!] $TOOL is not installed.\033[0m"
            read -p "Do you want to install $TOOL? (Y/N): " answer
            case $answer in
                [Yy]* )
                    echo -e "\033[1;34mInstalling $TOOL...\033[0m"
                    sudo apt update
                    sudo apt install -y "$TOOL"
                    ;;
                * )
                    echo -e "\033[1;33mSkipping $TOOL installation. This may cause issues later.\033[0m"
                    ;;
            esac
        else
            echo -e "\033[1;32m[+] $TOOL is already installed.\033[0m"
        fi
    done
}

# Function to check Volatility installation as a standalone directory
check_and_install_volatility() {
    VOL_DIR="volatility_2.6_lin64_standalone"
    VOL_ZIP="volatility_2.6_lin64_standalone.zip"
    if [ -d "$VOL_DIR" ]; then
        echo -e "\033[1;32m[+] Volatility is already installed.\033[0m"
    else
        echo -e "\033[1;31m[!] Volatility is not installed.\033[0m"
        read -p "Do you want to download and install Volatility 2.6 standalone? (Y/N): " answer
        case $answer in
            [Yy]* )
                echo -e "\033[1;34mDownloading Volatility 2.6...\033[0m"
                wget http://downloads.volatilityfoundation.org/releases/2.6/$VOL_ZIP
                unzip $VOL_ZIP
                chmod -R +x "$VOL_DIR"
                rm -f $VOL_ZIP
                echo -e "\033[1;32m[+] Volatility installed successfully!\033[0m"
                ;;
            * )
                echo -e "\033[1;33mSkipping Volatility installation. This may cause issues later.\033[0m"
                ;;
        esac
    fi
}

# Main flow
check_bulk_extractor
check_and_install_tools
check_and_install_volatility

# --- Next steps will be developed after this stage ---

# Create a main output directory with timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="Analysis_Output_$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

# Function to ensure full permissions for Volatility after download
fix_volatility_permissions() {
    VOL_DIR="volatility_2.6_lin64_standalone"
    if [ -d "$VOL_DIR" ]; then
        sudo chmod -R 777 "$VOL_DIR"
    fi
}

# Call after volatility installation
fix_volatility_permissions

# Prompt for file path
read -p "Enter the full path to the file you want to analyze: " FILE_PATH

# Check if file exists
if [ ! -f "$FILE_PATH" ]; then
    echo -e "\033[1;31m[!] File does not exist. Exiting.\033[0m"
    exit 1
fi

# Detect file type and extension
FILE_TYPE=$(file -b "$FILE_PATH")
FILE_EXT="${FILE_PATH##*.}"

# Determine memory image or disk image
IS_MEMORY=false

# Common memory keywords and extensions
MEMORY_KEYWORDS=("memory" "MemDump" "Windows memory" "Physical Memory" "VMEM" "hiberfil")
MEMORY_EXTENSIONS=("mem" "raw" "vmem" "bin" "dmp" "h5" "lime" "hibr")

# Check file type for memory keywords
for keyword in "${MEMORY_KEYWORDS[@]}"; do
    if [[ "$FILE_TYPE" == *"$keyword"* ]]; then
        IS_MEMORY=true
        break
    fi
done

# If not yet determined, check extension
if [ "$IS_MEMORY" = false ]; then
    for ext in "${MEMORY_EXTENSIONS[@]}"; do
        if [[ "$FILE_EXT" == "$ext" ]]; then
            IS_MEMORY=true
            break
        fi
    done
fi

if [ "$IS_MEMORY" = true ]; then
    echo -e "\033[1;36m[+] Memory image detected. Volatility will be used.\033[0m"
else
    echo -e "\033[1;36m[+] Disk/HDD image detected. Volatility will NOT be used.\033[0m"
fi

# Run all tools (excluding Volatility if not memory)
set_output_permissions() {
    sudo chmod -R 777 "$OUTPUT_DIR"
}

run_forensic_tools() {
    echo -e "\n\033[1;34m[*] Running bulk-extractor...\033[0m"
    (command -v bulk-extractor >/dev/null 2>&1 && bulk-extractor -o "$OUTPUT_DIR/bulk_extractor" -R "$FILE_PATH" > /dev/null 2>&1) \
        || (command -v bulk_extractor >/dev/null 2>&1 && bulk_extractor -o "$OUTPUT_DIR/bulk_extractor" -R "$FILE_PATH" > /dev/null 2>&1)

    echo -e "\n\033[1;34m[*] Running binwalk...\033[0m"
    binwalk "$FILE_PATH" > "$OUTPUT_DIR/binwalk.txt" 2>/dev/null

	echo -e "\n\033[1;34m[*] Running foremost...\033[0m"
	rm -rf "$OUTPUT_DIR/foremost"
	mkdir -p "$OUTPUT_DIR/foremost"
	sudo foremost -i "$FILE_PATH" -o "$OUTPUT_DIR/foremost" > "$OUTPUT_DIR/foremost_log.txt" 2>&1

# Remove the log file if it is empty or only contains 'Processing' and progress bar lines
if ! grep -Ev '^(Processing:|^\|[*]+\|$)' "$OUTPUT_DIR/foremost_log.txt" | grep -vq '^$'; then
    # Log file is empty or contains only non-informative lines, delete it
    rm -f "$OUTPUT_DIR/foremost_log.txt"
fi


    echo -e "\n\033[1;34m[*] Running strings...\033[0m"
    strings "$FILE_PATH" > "$OUTPUT_DIR/strings.txt" 2>/dev/null

    set_output_permissions
}

run_volatility_analysis() {
    VOL_PATH="./volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone"
    if [ ! -f "$VOL_PATH" ]; then
        echo -e "\033[1;31m[!] Volatility binary not found. Skipping Volatility analysis.\033[0m"
        return
    fi

    echo -e "\n\033[1;34m[*] Identifying possible profiles...\033[0m"
    # Save imageinfo output to file for reference and error checking
    "$VOL_PATH" -f "$FILE_PATH" imageinfo > "$OUTPUT_DIR/vol_imageinfo.txt" 2>&1
    PROFILES_RAW=$(grep "Suggested Profile" "$OUTPUT_DIR/vol_imageinfo.txt" | head -1 | awk -F':' '{print $2}' | cut -d'(' -f1 | tr -d ' ' | tr ',' '\n')

    PROFILES=()
    i=1
    if [[ -z "$PROFILES_RAW" ]]; then
        echo -e "\033[1;31m[!] Could not detect any Volatility profiles. Skipping.\033[0m"
        return
    fi

    echo "Available profiles:"
    while read -r profile; do
        if [[ -n "$profile" ]]; then
            PROFILES+=("$profile")
            echo "  [$i] $profile"
            ((i++))
        fi
    done <<< "$PROFILES_RAW"

    read -p "Select a profile number from the list above: " PROFILE_NUM
    PROFILE_SELECTED=${PROFILES[$((PROFILE_NUM-1))]}
    echo -e "\033[1;36m[+] Selected profile: $PROFILE_SELECTED\033[0m"

    # Run common Volatility plugins
echo -e "\n\033[1;34m[*] Running Volatility analysis (pslist)...\033[0m"
"$VOL_PATH" -f "$FILE_PATH" --profile="$PROFILE_SELECTED" pslist > "$OUTPUT_DIR/vol_pslist.txt" 2>&1

echo -e "\n\033[1;34m[*] Running Volatility analysis (connections)...\033[0m"
"$VOL_PATH" -f "$FILE_PATH" --profile="$PROFILE_SELECTED" connections > "$OUTPUT_DIR/vol_connections.txt" 2>&1

echo -e "\n\033[1;34m[*] Running Volatility analysis (hivelist, printkey)...\033[0m"
"$VOL_PATH" -f "$FILE_PATH" --profile="$PROFILE_SELECTED" hivelist > "$OUTPUT_DIR/vol_hivelist.txt" 2>&1
grep -E '^[0-9a-fA-Fx]+' "$OUTPUT_DIR/vol_hivelist.txt" | awk '{print $1}' | while read -r hive_addr; do
    "$VOL_PATH" -f "$FILE_PATH" --profile="$PROFILE_SELECTED" printkey -o "$hive_addr" -K 'SAM' >> "$OUTPUT_DIR/vol_sam_registry.txt" 2>&1
    "$VOL_PATH" -f "$FILE_PATH" --profile="$PROFILE_SELECTED" printkey -o "$hive_addr" -K 'SYSTEM' >> "$OUTPUT_DIR/vol_system_registry.txt" 2>&1
done

}

run_forensic_tools

if [ "$IS_MEMORY" = true ]; then
    run_volatility_analysis
fi

# Look for network captures (PCAP files)
PCAP_FOUND=$(find "$OUTPUT_DIR" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \))
if [ ! -z "$PCAP_FOUND" ]; then
    for f in $PCAP_FOUND; do
        SIZE=$(du -h "$f" | cut -f1)
        echo -e "\033[1;36m[+] Network traffic extracted: $f ($SIZE)\033[0m"
    done
fi

# Now print summary line:
echo -e "\n\033[1;32m[+] All outputs are saved in: $OUTPUT_DIR\033[0m"

REPORT="$OUTPUT_DIR/Forensics_Report.log"
echo "=========================================="         > "$REPORT"
echo "         Windows Forensics: Report"                 >> "$REPORT"
echo "        Generated: $(date '+%Y-%m-%d %H:%M:%S')"    >> "$REPORT"
echo "=========================================="         >> "$REPORT"

if [ -f "$OUTPUT_DIR/binwalk.txt" ]; then
    echo -e "\n[Binwalk Results]\n----------------"           >> "$REPORT"
    head -20 "$OUTPUT_DIR/binwalk.txt"                        >> "$REPORT"
    echo "  ... (see full in binwalk.txt)"                    >> "$REPORT"
fi

if [ -f "$OUTPUT_DIR/strings.txt" ]; then
    echo -e "\n[Interesting Strings]\n-------------------"    >> "$REPORT"
    grep -Ei '(password|secret|key|flag|token|user|admin)' "$OUTPUT_DIR/strings.txt" | head -10 >> "$REPORT"
    echo "  ... (see full in strings.txt)"                    >> "$REPORT"
fi

if [ -f "$OUTPUT_DIR/vol_pslist.txt" ]; then
    echo -e "\n[Volatility - Process List]\n----------------------" >> "$REPORT"
    head -20 "$OUTPUT_DIR/vol_pslist.txt"                    >> "$REPORT"
    echo "  ... (see full in vol_pslist.txt)"                >> "$REPORT"
fi

if [ -f "$OUTPUT_DIR/vol_connections.txt" ]; then
    echo -e "\n[Volatility - Connections]\n----------------------"   >> "$REPORT"
    head -20 "$OUTPUT_DIR/vol_connections.txt"               >> "$REPORT"
    echo "  ... (see full in vol_connections.txt)"           >> "$REPORT"
fi

if [ -f "$OUTPUT_DIR/vol_sam_registry.txt" ]; then
    echo -e "\n[Volatility - SAM Registry (accounts)]\n-----------------------------" >> "$REPORT"
    grep -Ei 'user|admin|account|login|name' "$OUTPUT_DIR/vol_sam_registry.txt" | head -10 >> "$REPORT"
    echo "  ... (see full in vol_sam_registry.txt)"           >> "$REPORT"
fi

if [ -f "$OUTPUT_DIR/vol_system_registry.txt" ]; then
    echo -e "\n[Volatility - SYSTEM Registry (keys)]\n-------------------------------" >> "$REPORT"
    grep -Ei 'controlset|policy|SID|key' "$OUTPUT_DIR/vol_system_registry.txt" | head -10 >> "$REPORT"
    echo "  ... (see full in vol_system_registry.txt)"        >> "$REPORT"
fi

if [ -d "$OUTPUT_DIR/bulk_extractor" ]; then
    echo -e "\n[Bulk Extractor Artifacts]\n------------------------"  >> "$REPORT"
    find "$OUTPUT_DIR/bulk_extractor" -type f | grep -v "\.zip$" | head -5 >> "$REPORT"
    echo "  ... (see full files in bulk_extractor/)"                  >> "$REPORT"
fi

if [ -d "$OUTPUT_DIR/foremost" ]; then
    echo -e "\n[Foremost Extracted Files]\n-------------------------"   >> "$REPORT"
    find "$OUTPUT_DIR/foremost" -type f | head -5                      >> "$REPORT"
    echo "  ... (see full files in foremost/)"                         >> "$REPORT"
fi

echo -e "\n==========================================" >> "$REPORT"
echo    "End of report. For full details, see output files in $OUTPUT_DIR" >> "$REPORT"
echo    "==========================================" >> "$REPORT"

echo -e "\033[1;32m[+] Forensics_Report.log created in $OUTPUT_DIR\033[0m"

# === Summary statistics ===
TOTAL_FILES=$(find "$OUTPUT_DIR" -type f | wc -l)
echo -e "\033[1;34m[*] Analysis time: $(date '+%Y-%m-%d %H:%M:%S')\033[0m"
echo -e "\033[1;34m[*] Total files extracted: $TOTAL_FILES\033[0m"

# Also add to report file
echo -e "\n[Summary Statistics]\n--------------------" >> "$OUTPUT_DIR/Forensics_Report.log"
echo "Analysis Time: $(date '+%Y-%m-%d %H:%M:%S')" >> "$OUTPUT_DIR/Forensics_Report.log"
echo "Total Files Extracted: $TOTAL_FILES" >> "$OUTPUT_DIR/Forensics_Report.log"

# === Create ZIP archive of all outputs ===
ZIPNAME="${OUTPUT_DIR}.zip"
zip -r "$ZIPNAME" "$OUTPUT_DIR" >/dev/null 2>&1
echo -e "\033[1;32m[+] All extracted files and the report have been zipped to: $ZIPNAME\033[0m"
