import subprocess
import sys

def run_stage_gate():
    print('[*] Running Honeycomb Stage Gate Verification...')
    result = subprocess.run([sys.executable, '-m', 'pytest', '-v', '--basetemp=./.pytest_tmp'])
    if result.returncode == 0:
        print('\n[+] STAGE GATE PASSED: All pipeline tests and validations are successful!')
        sys.exit(0)
    else:
        print('\n[-] STAGE GATE FAILED: Some tests did not pass.')
        sys.exit(1)

if __name__ == '__main__':
    run_stage_gate()
