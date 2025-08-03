# coding = 'utf-8'

import os
import sys
import subprocess

self_dir = os.path.dirname(os.path.abspath(__file__))
pip_path = os.path.dirname(os.path.abspath(sys.executable))
pip_path = (f'{pip_path}\\Scripts' 
            if os.path.exists(f'{pip_path}\\Scripts') else pip_path
)


def main():
    command = [sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip']
    subprocess.run(command, shell=True, check=True)
    command = [f'{pip_path}\\pip.exe', 'install', '-r', f'{self_dir}\\p_install.txt']
    subprocess.run(command, shell=True, check=True)
    subprocess.run(['exit'], shell=True, check=True)


if __name__ == '__main__':
    main()
