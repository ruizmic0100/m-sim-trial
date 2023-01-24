import os
import subprocess
import sys
import argparse


def run_standard(int_reg_cap):
    command = f"cd ../spec2006/ && ../m-sim-trial/m-sim/sim-outorder -rf:size 160 -max_contexts_per_core 4 -int_reg_cap {int_reg_cap} astarNS.1.arg dealIINS.1.arg gobmkNS.1.arg lbmNS.1.arg"
    subprocess.run(command, shell=True);

def run_mix(int_reg_cap):
    for run in range(1, 33):
        command = f"cd ../spec2006/ && ../m-sim-trial/m-sim/sim-outorder -rf:size 160 -max_contexts_per_core 4 -int_reg_cap {run} astarNS.1.arg dealIINS.1.arg gobmkNS.1.arg lbmNS.1.arg"
        subprocess.run(command, shell=True);
    for run in range(1, 33):
        command = f"cd ../spec2006/ && ../m-sim-trial/m-sim/sim-outorder -rf:size 160 -max_contexts_per_core 4 -int_reg_cap {run} astarNS.1.arg gccNS.1.arg lbmNS.1.arg namdNS.1.arg"
        subprocess.run(command, shell=True);
    for run in range(1, 33):
        command = f"cd ../spec2006/ && ../m-sim-trial/m-sim/sim-outorder -rf:size 160 -max_contexts_per_core 4 -int_reg_cap {run} astarNS.1.arg gobmkNS.1.arg milcNS.1.arg sjengNS.1.arg"
        subprocess.run(command, shell=True);
    for run in range(1, 33):
        command = f"cd ../spec2006/ && ../m-sim-trial/m-sim/sim-outorder -rf:size 160 -max_contexts_per_core 4 -int_reg_cap {run} bzip2NS.1.arg dealIINS.1.arg gccNS.1.arg gobmkNS.1.arg"
        subprocess.run(command, shell=True);

def run_basic_mix(int_reg_cap):
    for run in range(1, 33):
        command = f"cd ../spec2006/ && ../m-sim-trial/m-sim/sim-outorder -rf:size 160 -max_contexts_per_core 4 -int_reg_cap {run} astarNS.1.arg dealIINS.1.arg gobmkNS.1.arg lbmNS.1.arg"
        subprocess.run(command, shell=True);

FUNCTION_MAP = {'run_standard' : run_standard,
                'run_shmix' : run_mix,
                'run_basic_shmix' : run_basic_mix }

parser = argparse.ArgumentParser(description='run m-sim')

parser.add_argument('command', choices=FUNCTION_MAP.keys(),
                    help='run a single four thread mix of different benchmarks.')

parser.add_argument('int_reg_cap', nargs='?', type=int)

args = parser.parse_args()

if __name__ == "__main__":
    func = FUNCTION_MAP[args.command]
    func(args.int_reg_cap)