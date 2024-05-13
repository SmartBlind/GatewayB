import subprocess
import threading
import sys

def install_dependencies():
    """ Install necessary dependencies Rust and Node.js if needed. """
    if sys.platform.startswith('win'):
        if not command_available("cargo --version"):
            print("Installing Rust via winget...")
            subprocess.run("winget install --id=Rustlang.Rustup -e --silent", shell=True, check=True)
        if not command_available("node --version"):
            print("Installing Node.js via winget...")
            subprocess.run("winget install --id=OpenJS.NodeJS -e --silent", shell=True, check=True)
    else:
        if not command_available("cargo --version"):
            print("Installing Rust...")
            subprocess.run("curl https://sh.rustup.rs -sSf | sh -s -- -y", shell=True, check=True)
        if not command_available("node --version"):
            print("Installing Node.js...")
            subprocess.run("curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash", shell=True, check=True)
            subprocess.run("export NVM_DIR=\"$HOME/.nvm\" && [ -s \"$NVM_DIR/nvm.sh\" ] && \\. \"$NVM_DIR/nvm.sh\"; nvm install node && nvm use node", shell=True, check=True)

def command_available(command):
    """ Check if the command is available on the system. """
    try:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def run_command(command, prefix):
    """ Helper function to run a command in the shell and print the output. """
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(f"{prefix}: {line}", end='')
        process.stdout.close()
        return_code = process.wait()
        if return_code:
            raise subprocess.CalledProcessError(return_code, command)
    except Exception as e:
            print(f"{prefix} Error: An unexpected error occurred while executing {command}: {e}")

def run_in_thread(command, prefix):
    """ Run commands in a separate thread. """
    thread = threading.Thread(target=run_command, args=(command, prefix))
    thread.start()
    return thread

def main():
    user_input = input("Do you want to run the mock service? (Press Enter or 'y/yes' for yes; any other key for no): ").strip().lower()
    use_mock = user_input == '' or user_input in ['y', 'yes']

    install_dependencies()

    run_command("npm install", "\033[0;31m[Npm]\033[0;0m")

    run_command("cargo install sqlx-cli", "\033[0;31m[Cargo]\033[0;0m")

    threads = []

    if use_mock:
        threads.append(run_in_thread("cargo run --package lumisync-mock --bin mock", "\033[0;33m[Mock]\033[0;0m"))

    threads.append(run_in_thread("cargo run --package lumisync-server --bin server", "\033[0;34m[Server]\033[0;0m"))
    threads.append(run_in_thread("npm run web", "\033[0;32m[Web]\033[0;0m"))

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()