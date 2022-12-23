import os
import subprocess

if __name__ == "__main__":
    subprocess.run("cd ../spec2006/ && ../m-sim-trial/m-sim/sim-outorder -rf:size 128 astarNS.1.arg dealIINS.1.arg", shell=True);
