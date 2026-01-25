import requests
import sys

# Configuration
URL = 'http://challenges4.ctf.sd:34844/console'
JWT = ''
COOKIES = {'jwt': JWT}

def main():
    print("=== 0xROUTER INTERACTIVE CONSOLE ===")
    print("Type 'exit' to quit.\n")
    
    while True:
        try:
            # Prompt for input
            cmd = input("ctf@0xrouter:$ ").strip()
            
            if cmd.lower() in ['exit', 'quit']:
                break
            if not cmd:
                continue

            # Send request
            # Note: requests.get handles URL encoding for the 'cmd' param automatically
            r = requests.get(URL, params={'cmd': cmd}, cookies=COOKIES)
            
            # Print response
            if r.status_code == 200:
                print(r.text)
            else:
                print(f"Error {r.status_code}: {r.text}")

        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Request failed: {e}")

if __name__ == "__main__":
    main()
