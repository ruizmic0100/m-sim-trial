# Finding throughput IPC and saving that result and then displaying it on a graph.
import matplotlib.pyplot as plt

total_sim_runs_path = f'./simulation-results/total_sim_runs.txt'
reg_cap = [8, 9, 10, 32]
throughput_ipc = [None] * len(reg_cap)

def get_throughput_ipc(total_runs):
    i = 0
    while i < total_runs:
        with open(f'./simulation-results/run_{i+1}.txt', 'r') as file:
            content = file.read()
            subtr_target = content.find("THROUGHPUT IPC: ")
            throughput_ipc[i] = float(content[subtr_target+16:subtr_target+16+8])
            i += 1
        file.close()

with open(total_sim_runs_path, 'r') as total_runs_file:
    data = total_runs_file.read()
    total_runs = data[0]
    get_throughput_ipc(int(total_runs))

    print(throughput_ipc)


    plt.plot(reg_cap, throughput_ipc)
    plt.title("Register Capping vs. IPC Throughput")
    plt.ylabel("IPC Throughput")
    plt.xlabel("Register Cap Value")


    plt.show()

