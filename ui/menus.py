import os
import getpass
import sys
import shutil
from pystyle import Colorate, Colors as PystyleColors
from ui.display import clear_screen, display_header, pause_and_continue, align_gradient_text, gradient_print, get_midnight_gradient_text
from ui.colors import Colors as OldColors
from crypto.encryption import EncryptionService
from crypto.hashing import calculate_hash_text, calculate_hash_file, get_hash_algorithm
from crypto.password_gen import generate_password
from network.scanner import perform_port_scan, perform_smart_port_scan
from network.dns_lookup import perform_dns_lookup
from network.web_tools import (
    get_http_headers_interactive,
    get_website_cookies_interactive,
    perform_whois_lookup_interactive,
)
from utils.encoding import base64_encode, base64_decode, hex_encode, hex_decode
from utils.system_info import display_system_info, list_running_processes
from config import Config


def get_terminal_width() -> int:
    try:
        width, _ = shutil.get_terminal_size()
        return width
    except:
        return 120


def get_password(prompt: str = None) -> str:
    if prompt is None:
        prompt = get_midnight_gradient_text("Enter secret key (input hidden): ")
    
    try:
        p = getpass.getpass(prompt)
        if not p:
            gradient_print("[!] Secret key cannot be empty.")
            return None
        return p
    except KeyboardInterrupt:
        gradient_print("\n[!] Operation cancelled by user.")
        return None
    except Exception as e:
        gradient_print(f"[!] Error reading secret key: {e}")
        return None


class CryptoMenu:
    
    @staticmethod
    def run():
        while True:
            clear_screen()
            display_header()
            
            menu_box = f"""
{PystyleColors.purple}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}                                                                              {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {align_gradient_text("              CRYPTOGRAPHY TOOLS", 70, lambda t: Colorate.Horizontal(PystyleColors.purple_to_blue, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}                                                                              {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[1]{PystyleColors.reset}  {align_gradient_text("Encrypt Text Message", 60, lambda t: Colorate.Horizontal(PystyleColors.purple_to_blue, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[2]{PystyleColors.reset}  {align_gradient_text("Decrypt Text Message", 60, lambda t: Colorate.Horizontal(PystyleColors.blue_to_purple, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[3]{PystyleColors.reset}  {align_gradient_text("Encrypt File", 60, lambda t: Colorate.Horizontal(PystyleColors.purple_to_blue, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[4]{PystyleColors.reset}  {align_gradient_text("Decrypt File", 60, lambda t: Colorate.Horizontal(PystyleColors.blue_to_purple, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[5]{PystyleColors.reset}  {align_gradient_text("Hash Calculator (MD5, SHA...)", 60, lambda t: Colorate.Horizontal(PystyleColors.purple_to_blue, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[6]{PystyleColors.reset}  {align_gradient_text("Generate Strong Password", 60, lambda t: Colorate.Horizontal(PystyleColors.blue_to_purple, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[0]{PystyleColors.reset}  {PystyleColors.red}Back to Main Menu{PystyleColors.reset:<45}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}                                                                              {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.purple}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{PystyleColors.reset}
"""
            print(menu_box)
            prompt_text = "┌──(user@midnight)-[~/crypto]\n└─$ "
            choice = input(get_midnight_gradient_text(prompt_text))
            
            if choice == '1':
                password = get_password()
                if not password:
                    pause_and_continue()
                    continue
                message = input(get_midnight_gradient_text("Enter the message to encrypt: "))
                if not message:
                    gradient_print("Message cannot be empty.")
                    pause_and_continue()
                    continue
                gradient_print("\n[*] Encrypting...")
                encrypted = EncryptionService.encrypt_message(password, message)
                if encrypted:
                    gradient_print(f"[+] Ciphertext: {encrypted}")
                pause_and_continue()
            
            elif choice == '2':
                password = get_password()
                if not password:
                    pause_and_continue()
                    continue
                encrypted_data = input(get_midnight_gradient_text("Enter ciphertext: "))
                if not encrypted_data:
                    gradient_print("Ciphertext cannot be empty.")
                    pause_and_continue()
                    continue
                gradient_print("\n[*] Decrypting...")
                decrypted = EncryptionService.decrypt_message(password, encrypted_data)
                if decrypted:
                    gradient_print(f"[+] Plaintext: {decrypted}")
                pause_and_continue()
            
            elif choice == '3':
                password = get_password()
                if not password:
                    pause_and_continue()
                    continue
                input_file = input(get_midnight_gradient_text("File to encrypt: "))
                default_output = f"{input_file}.enc"
                output_file = input(get_midnight_gradient_text(f"Output file (default: {default_output}): ")) or default_output
                if not os.path.exists(input_file):
                    gradient_print("Input file not found.")
                    pause_and_continue()
                    continue
                if os.path.abspath(input_file) == os.path.abspath(output_file):
                    gradient_print("Input/output cannot be same.")
                    pause_and_continue()
                    continue
                gradient_print("\n[*] Encrypting file...")
                success = EncryptionService.encrypt_file(password, input_file, output_file)
                if success:
                    gradient_print(f"[+] File encrypted successfully to '{output_file}'")
                pause_and_continue()
            
            elif choice == '4':
                password = get_password()
                if not password:
                    pause_and_continue()
                    continue
                input_file = input(get_midnight_gradient_text("File to decrypt (.enc): "))
                default_output = input_file.replace('.enc', '.dec') if input_file.endswith('.enc') else f"{input_file}.dec"
                output_file = input(get_midnight_gradient_text(f"Output file (default: {default_output}): ")) or default_output
                if not os.path.exists(input_file):
                    gradient_print("Input file not found.")
                    pause_and_continue()
                    continue
                if os.path.abspath(input_file) == os.path.abspath(output_file):
                    gradient_print("Input/output cannot be same.")
                    pause_and_continue()
                    continue
                gradient_print("\n[*] Decrypting file...")
                success = EncryptionService.decrypt_file(password, input_file, output_file)
                if success:
                    gradient_print(f"[+] File decrypted successfully to '{output_file}'")
                pause_and_continue()
            
            elif choice == '5':
                CryptoMenu._calculate_hash()
                pause_and_continue()
            
            elif choice == '6':
                CryptoMenu._generate_password()
                pause_and_continue()
            
            elif choice == '0':
                break
            else:
                gradient_print("Invalid choice.")
                pause_and_continue()
    
    @staticmethod
    def _calculate_hash():
        gradient_print("--- Hash Calculator ---")
        gradient_print("[1] Hash Text Input")
        gradient_print("[2] Hash File")
        gradient_print("[0] Back to Crypto Menu")
        choice = input(get_midnight_gradient_text("Select hash source: "))
        
        if choice not in ['1', '2']:
            if choice != '0':
                print(f"{PystyleColors.red}Invalid choice.{PystyleColors.reset}")
            return
        
        gradient_print("\nAvailable Algorithms:")
        gradient_print("[1] MD5")
        gradient_print("[2] SHA-1")
        gradient_print("[3] SHA-256")
        gradient_print("[4] SHA-512")
        algo_choice = input(get_midnight_gradient_text("Select algorithm: "))
        
        algo_map = {
            '1': 'md5',
            '2': 'sha1',
            '3': 'sha256',
            '4': 'sha512',
        }
        
        if algo_choice not in algo_map:
            gradient_print("Invalid algorithm choice.")
            return
        
        algo_name = algo_map[algo_choice]
        algo_display = ['MD5', 'SHA-1', 'SHA-256', 'SHA-512'][int(algo_choice) - 1]
        
        try:
            if choice == '1':
                text_input = input(get_midnight_gradient_text("Enter text to hash: "))
                if not text_input:
                    gradient_print("Input text cannot be empty.")
                    return
                hash_result = calculate_hash_text(text_input, algo_name)
                if hash_result:
                    gradient_print(f"\n{algo_display} Hash: {hash_result}")
            
            elif choice == '2':
                file_path = input(get_midnight_gradient_text("Enter path to file: "))
                if not os.path.isfile(file_path):
                    gradient_print(f"File not found: '{file_path}'")
                    return
                gradient_print(f"Hashing file '{os.path.basename(file_path)}'...")
                hash_result = calculate_hash_file(file_path, algo_name)
                if hash_result:
                    gradient_print(f"\n{algo_display} Hash: {hash_result}")
        
        except Exception as e:
            gradient_print(f"[!] Error during hashing: {e}")
    
    @staticmethod
    def _generate_password():
        gradient_print("--- Strong Password Generator ---")
        try:
            length = int(input(get_midnight_gradient_text("Enter desired password length (e.g., 16): ")))
            if length < 8:
                gradient_print("Warning: Length less than 8 is generally not recommended.")
            if length <= 0:
                gradient_print("Length must be positive.")
                return
            
            use_uppercase = input(get_midnight_gradient_text("Include uppercase letters? (y/n): ")).lower() == 'y'
            use_lowercase = input(get_midnight_gradient_text("Include lowercase letters? (y/n): ")).lower() == 'y'
            use_digits = input(get_midnight_gradient_text("Include digits? (y/n): ")).lower() == 'y'
            use_symbols = input(get_midnight_gradient_text("Include symbols? (y/n): ")).lower() == 'y'
            
            password = generate_password(length, use_uppercase, use_lowercase, use_digits, use_symbols)
            if password:
                gradient_print(f"\nGenerated Password: {password}")
        
        except ValueError:
            gradient_print("Invalid length. Please enter a number.")
        except Exception as e:
            gradient_print(f"Error generating password: {e}")


class NetworkMenu:
    
    @staticmethod
    def run():
        while True:
            clear_screen()
            display_header()
            
            menu_box = f"""
{PystyleColors.purple}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}                                                                              {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {align_gradient_text("                 NETWORK TOOLS", 70, lambda t: Colorate.Horizontal(PystyleColors.purple_to_blue, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}                                                                              {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[1]{PystyleColors.reset}  {align_gradient_text("Basic Port Scanner", 60, lambda t: Colorate.Horizontal(PystyleColors.purple_to_blue, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[2]{PystyleColors.reset}  {align_gradient_text("Smart Port Scanner", 60, lambda t: Colorate.Horizontal(PystyleColors.blue_to_purple, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[3]{PystyleColors.reset}  {align_gradient_text("Whois Domain Lookup", 60, lambda t: Colorate.Horizontal(PystyleColors.purple_to_blue, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[4]{PystyleColors.reset}  {align_gradient_text("DNS Record Lookup", 60, lambda t: Colorate.Horizontal(PystyleColors.blue_to_purple, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[5]{PystyleColors.reset}  {align_gradient_text("Get HTTP Headers", 60, lambda t: Colorate.Horizontal(PystyleColors.purple_to_blue, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[6]{PystyleColors.reset}  {align_gradient_text("Get Website Cookies", 60, lambda t: Colorate.Horizontal(PystyleColors.blue_to_purple, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[0]{PystyleColors.reset}  {PystyleColors.red}Back to Main Menu{PystyleColors.reset:<45}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}                                                                              {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.purple}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{PystyleColors.reset}
"""
            print(menu_box)
            prompt_text = "┌──(user@midnight)-[~/network]\n└─$ "
            choice = input(get_midnight_gradient_text(prompt_text))
            
            if choice == '1':
                perform_port_scan()
                pause_and_continue()
            elif choice == '2':
                perform_smart_port_scan()
                pause_and_continue()
            elif choice == '3':
                perform_whois_lookup_interactive()
                pause_and_continue()
            elif choice == '4':
                perform_dns_lookup()
                pause_and_continue()
            elif choice == '5':
                get_http_headers_interactive()
                pause_and_continue()
            elif choice == '6':
                get_website_cookies_interactive()
                pause_and_continue()
            elif choice == '0':
                break
            else:
                gradient_print("Invalid choice.")
                pause_and_continue()


class DataMenu:
    
    @staticmethod
    def run():
        while True:
            clear_screen()
            display_header()
            
            menu_box = f"""
{PystyleColors.purple}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}                                                                              {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {align_gradient_text("                 DATA UTILITIES", 70, lambda t: Colorate.Horizontal(PystyleColors.purple_to_blue, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}                                                                              {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[1]{PystyleColors.reset}  {align_gradient_text("Encode/Decode (Base64, Hex)", 60, lambda t: Colorate.Horizontal(PystyleColors.purple_to_blue, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[0]{PystyleColors.reset}  {PystyleColors.red}Back to Main Menu{PystyleColors.reset:<45}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}                                                                              {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.purple}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{PystyleColors.reset}
"""
            print(menu_box)
            prompt_text = "┌──(user@midnight)-[~/data]\n└─$ "
            choice = input(get_midnight_gradient_text(prompt_text))
            
            if choice == '1':
                DataMenu._encode_decode_data()
                pause_and_continue()
            elif choice == '0':
                break
            else:
                gradient_print("Invalid choice.")
                pause_and_continue()
    
    @staticmethod
    def _encode_decode_data():
        gradient_print("--- Data Encoder/Decoder ---")
        gradient_print("[1] Base64 Encode")
        gradient_print("[2] Base64 Decode")
        gradient_print("[3] Hex Encode")
        gradient_print("[4] Hex Decode")
        gradient_print("[0] Back to Data Utilities Menu")
        choice = input(get_midnight_gradient_text("Select operation: "))
        
        if choice == '0':
            return
        if choice not in ['1', '2', '3', '4']:
            gradient_print("Invalid choice.")
            return
        
        data_input = input(get_midnight_gradient_text("Enter data: "))
        if not data_input:
            gradient_print("Input data cannot be empty.")
            return
        
        try:
            result = None
            if choice == '1':
                result = base64_encode(data_input)
                if result:
                    gradient_print(f"\nBase64 Encoded: {result}")
            elif choice == '2':
                result = base64_decode(data_input)
                if result:
                    gradient_print(f"\nBase64 Decoded: {result}")
            elif choice == '3':
                result = hex_encode(data_input)
                if result:
                    gradient_print(f"\nHex Encoded: {result}")
            elif choice == '4':
                result = hex_decode(data_input)
                if result:
                    gradient_print(f"\nHex Decoded: {result}")
        
        except Exception as e:
            gradient_print(f"[!] An unexpected error occurred: {e}")


class SystemMenu:
    
    @staticmethod
    def run():
        while True:
            clear_screen()
            display_header()
            
            menu_box = f"""
{PystyleColors.purple}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}                                                                              {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {align_gradient_text("               SYSTEM UTILITIES", 70, lambda t: Colorate.Horizontal(PystyleColors.purple_to_blue, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}                                                                              {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[1]{PystyleColors.reset}  {align_gradient_text("Display System Information", 60, lambda t: Colorate.Horizontal(PystyleColors.purple_to_blue, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[2]{PystyleColors.reset}  {align_gradient_text("List Running Processes", 60, lambda t: Colorate.Horizontal(PystyleColors.blue_to_purple, t))}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}  {PystyleColors.light_blue}[0]{PystyleColors.reset}  {PystyleColors.red}Back to Main Menu{PystyleColors.reset:<45}  {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.blue}┃{PystyleColors.reset}                                                                              {PystyleColors.blue}┃{PystyleColors.reset}
{PystyleColors.purple}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{PystyleColors.reset}
"""
            print(menu_box)
            prompt_text = "┌──(user@midnight)-[~/system]\n└─$ "
            choice = input(get_midnight_gradient_text(prompt_text))
            
            if choice == '1':
                display_system_info()
                pause_and_continue()
            elif choice == '2':
                list_running_processes()
                pause_and_continue()
            elif choice == '0':
                break
            else:
                gradient_print("Invalid choice.")
                pause_and_continue()


class MainMenu:
    
    @staticmethod
    def _print_menu():
        clear_screen()
        display_header()
        
        width = get_terminal_width()
        
        section_width = width // 3
        box_border_length = section_width - 2
        box_full_width = box_border_length + 2
        
        total_boxes_width = box_full_width * 3
        
        left_padding = (width - total_boxes_width) // 2
        padding_str = ' ' * left_padding
        
        header_line = "╓" + "─" * box_border_length + "╖" + "╓" + "─" * box_border_length + "╖" + "╓" + "─" * box_border_length + "╖"
        print(padding_str + Colorate.Horizontal(PystyleColors.purple_to_blue, header_line))
        
        cat1_text = "NETWORK SCANNERS"
        cat2_text = "CRYPTOGRAPHY"
        cat3_text = "UTILITIES"
        
        cat1_padding_left = (box_border_length - len(cat1_text)) // 2
        cat1_padding_right = box_border_length - len(cat1_text) - cat1_padding_left
        cat1 = " " * cat1_padding_left + cat1_text + " " * cat1_padding_right
        
        cat2_padding_left = (box_border_length - len(cat2_text)) // 2
        cat2_padding_right = box_border_length - len(cat2_text) - cat2_padding_left
        cat2 = " " * cat2_padding_left + cat2_text + " " * cat2_padding_right
        
        cat3_padding_left = (box_border_length - len(cat3_text)) // 2
        cat3_padding_right = box_border_length - len(cat3_text) - cat3_padding_left
        cat3 = " " * cat3_padding_left + cat3_text + " " * cat3_padding_right
        
        categories_text = cat1 + cat2 + cat3
        print(padding_str + Colorate.Horizontal(PystyleColors.purple_to_blue, categories_text))
        
        footer_line = "╙" + "─" * box_border_length + "╜" + "╙" + "─" * box_border_length + "╜" + "╙" + "─" * box_border_length + "╜"
        print(padding_str + Colorate.Horizontal(PystyleColors.purple_to_blue, footer_line))
        
        line1 = f"├─ [01] Port Scanner".ljust(box_full_width) + f"├─ [07] Encrypt Text".ljust(box_full_width) + f"├─ [12] Encode/Decode".ljust(box_full_width)
        print(padding_str + Colorate.Horizontal(PystyleColors.purple_to_blue, line1))
        
        line2 = f"├─ [02] Smart Scanner".ljust(box_full_width) + f"├─ [08] Decrypt Text".ljust(box_full_width) + f"├─ [13] Password Gen".ljust(box_full_width)
        print(padding_str + Colorate.Horizontal(PystyleColors.purple_to_blue, line2))
        
        line3 = f"├─ [03] Whois Lookup".ljust(box_full_width) + f"├─ [09] Encrypt File".ljust(box_full_width) + f"├─ [14] System Info".ljust(box_full_width)
        print(padding_str + Colorate.Horizontal(PystyleColors.purple_to_blue, line3))
        
        line4 = f"├─ [04] DNS Lookup".ljust(box_full_width) + f"├─ [10] Decrypt File".ljust(box_full_width) + f"├─ [15] Processes".ljust(box_full_width)
        print(padding_str + Colorate.Horizontal(PystyleColors.purple_to_blue, line4))
        
        line5 = f"└─ [05] HTTP Headers".ljust(box_full_width) + f"└─ [11] Hash Calculator".ljust(box_full_width) + f"└─ [16] Coming Soon...".ljust(box_full_width)
        print(padding_str + Colorate.Horizontal(PystyleColors.purple_to_blue, line5))
        
        nav_text = "├─ [E] Exit"
        nav_line = "".rjust(width - len(nav_text)) + nav_text
        print(Colorate.Horizontal(PystyleColors.purple_to_blue, nav_line))
        print()
    
    @staticmethod
    def run():
        while True:
            MainMenu._print_menu()
            prompt_text = "┌──(user@midnight)-[~/main]\n└─$ "
            prompt_gradient = Colorate.Horizontal(PystyleColors.purple_to_blue, prompt_text)
            choice = input(prompt_gradient)
            
            if choice.lower() == 'e':
                clear_screen()
                from ui.display import get_ascii_art_with_frame
                print(get_ascii_art_with_frame())
                gradient_print("\n[*] Terminating MIDNIGHT MULTI-TOOL Session... Stay safe! 🌙")
                sys.exit(0)
            
            elif choice == '01':
                perform_port_scan()
                pause_and_continue()
            elif choice == '02':
                perform_smart_port_scan()
                pause_and_continue()
            elif choice == '03':
                perform_whois_lookup_interactive()
                pause_and_continue()
            elif choice == '04':
                perform_dns_lookup()
                pause_and_continue()
            elif choice == '05':
                get_http_headers_interactive()
                pause_and_continue()
            elif choice == '06':
                get_website_cookies_interactive()
                pause_and_continue()
            
            elif choice == '07':
                password = get_password()
                if not password:
                    pause_and_continue()
                    continue
                message = input(get_midnight_gradient_text("Enter the message to encrypt: "))
                if not message:
                    gradient_print("Message cannot be empty.")
                    pause_and_continue()
                    continue
                gradient_print("\n[*] Encrypting...")
                encrypted = EncryptionService.encrypt_message(password, message)
                if encrypted:
                    gradient_print(f"[+] Ciphertext: {encrypted}")
                pause_and_continue()
            elif choice == '08':
                password = get_password()
                if not password:
                    pause_and_continue()
                    continue
                encrypted_data = input(get_midnight_gradient_text("Enter ciphertext: "))
                if not encrypted_data:
                    gradient_print("Ciphertext cannot be empty.")
                    pause_and_continue()
                    continue
                gradient_print("\n[*] Decrypting...")
                decrypted = EncryptionService.decrypt_message(password, encrypted_data)
                if decrypted:
                    gradient_print(f"[+] Plaintext: {decrypted}")
                pause_and_continue()
            elif choice == '09':
                password = get_password()
                if not password:
                    pause_and_continue()
                    continue
                input_file = input(get_midnight_gradient_text("File to encrypt: "))
                default_output = f"{input_file}.enc"
                output_file = input(get_midnight_gradient_text(f"Output file (default: {default_output}): ")) or default_output
                if not os.path.exists(input_file):
                    gradient_print("Input file not found.")
                    pause_and_continue()
                    continue
                if os.path.abspath(input_file) == os.path.abspath(output_file):
                    gradient_print("Input/output cannot be same.")
                    pause_and_continue()
                    continue
                gradient_print("\n[*] Encrypting file...")
                success = EncryptionService.encrypt_file(password, input_file, output_file)
                if success:
                    gradient_print(f"[+] File encrypted successfully to '{output_file}'")
                pause_and_continue()
            elif choice == '10':
                password = get_password()
                if not password:
                    pause_and_continue()
                    continue
                input_file = input(get_midnight_gradient_text("File to decrypt (.enc): "))
                default_output = input_file.replace('.enc', '.dec') if input_file.endswith('.enc') else f"{input_file}.dec"
                output_file = input(get_midnight_gradient_text(f"Output file (default: {default_output}): ")) or default_output
                if not os.path.exists(input_file):
                    gradient_print("Input file not found.")
                    pause_and_continue()
                    continue
                if os.path.abspath(input_file) == os.path.abspath(output_file):
                    gradient_print("Input/output cannot be same.")
                    pause_and_continue()
                    continue
                gradient_print("\n[*] Decrypting file...")
                success = EncryptionService.decrypt_file(password, input_file, output_file)
                if success:
                    gradient_print(f"[+] File decrypted successfully to '{output_file}'")
                pause_and_continue()
            elif choice == '11':
                CryptoMenu._calculate_hash()
                pause_and_continue()
            
            elif choice == '12':
                DataMenu._encode_decode_data()
                pause_and_continue()
            elif choice == '13':
                CryptoMenu._generate_password()
                pause_and_continue()
            elif choice == '14':
                display_system_info()
                pause_and_continue()
            elif choice == '15':
                list_running_processes()
                pause_and_continue()
            elif choice == '16':
                gradient_print("[*] Coming soon...")
                pause_and_continue()
            
            else:
                gradient_print("[!] Invalid choice. Please select a valid option.")
                pause_and_continue()
