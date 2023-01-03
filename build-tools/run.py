import os
import subprocess

if __name__ == "__main__":
    subprocess.run("cd ../spec2006/ && ../m-sim-trial/m-sim_v3.0/sim-outorder -rf:size 160 -max_contexts_per_core 4 -int_reg_cap 32 astarNS.1.arg dealIINS.1.arg gobmkNS.1.arg lbmNS.1.arg", shell=True);
