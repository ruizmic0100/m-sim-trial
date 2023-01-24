# Finding throughput IPC and saving that result and then displaying it on a graph.
import matplotlib.pyplot as plt

total_sim_runs_path = './simulation-results/total_sim_runs.txt'
reg_cap = [i for i in range(1,33)]
throughput_ipc_1 = [None] * 32
throughput_ipc_2 = [None] * 32
throughput_ipc_3 = [None] * 32
throughput_ipc_4 = [None] * 32

def get_throughput_ipc(total_runs):
    if total_runs == 32:
        for i in range(0,32):
            with open(f'./simulation-results/run_{i+1}.txt', 'r') as file:
                content = file.read()
                subtr_target = content.find("THROUGHPUT IPC: ")
                throughput_ipc_1[i] = float(content[subtr_target+16:subtr_target+16+8])
                file.close()
    if total_runs == 64:
        for i in range(0,32):
            with open(f'./simulation-results/run_{i+1}.txt', 'r') as file:
                content = file.read()
                subtr_target = content.find("THROUGHPUT IPC: ")
                throughput_ipc_2[i] = float(content[subtr_target+16:subtr_target+16+8])
                file.close()
    if total_runs == 96:
        for i in range(0,32):
            with open(f'./simulation-results/run_{i+1}.txt', 'r') as file:
                content = file.read()
                subtr_target = content.find("THROUGHPUT IPC: ")
                throughput_ipc_3[i] = float(content[subtr_target+16:subtr_target+16+8])
                file.close()
    if total_runs == 128:
        for i in range(0,32):
            with open(f'./simulation-results/run_{i+1}.txt', 'r') as file:
                content = file.read()
                subtr_target = content.find("THROUGHPUT IPC: ")
                throughput_ipc_4[i] = float(content[subtr_target+16:subtr_target+16+8])
                file.close()



with open(total_sim_runs_path, 'r') as total_runs_file:
    data = total_runs_file.read()
    total_runs = [ int(x) for x in data.split() ]
    get_throughput_ipc(total_runs[0])
    print(throughput_ipc_1)
    print("\n\n")
    print(throughput_ipc_2)


    print(max(throughput_ipc_1))
    percentage_1 = ((max(throughput_ipc_1) - throughput_ipc_1[31]) / throughput_ipc_1[31])
    print(percentage_1 * 100)

    if total_runs[0] == 32:
        plt.figure(1)
        plt.plot(reg_cap, throughput_ipc_1)
        plt.title("Register Capping vs. IPC Throughput")
        plt.ylabel("IPC Throughput")
        plt.xlabel("Register Cap Value")

    if total_runs[0] == 64:
        plt.figure(2)
        plt.plot(reg_cap, throughput_ipc_2)
        plt.title("Register Capping vs. IPC Throughput_2")
        plt.ylabel("IPC Throughput")
        plt.xlabel("Register Cap Value")
        
        
    plt.show()