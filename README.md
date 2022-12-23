
# M-Sim Trial

Verify if using a static cap on extra register usage for threads improves overall throughput IPC.




## Demo
---

Insert gif or link to demo


## Installation/Building
---

Clone the repository

```bash
  git clone m-sim trial
```

Add benchmark to path
```bash
  export PATH=/path/to/benchmark_directory/:$PATH
```

Use the build script at root directory of repository
```bash
  pwd
  /home/username/m-sim-trial/ # Correct!
  /home/username/m-sim-trial/build-tools/ # Wrong!
  ./build-tools/build.sh
```
    
## Lessons Learned
---

What did you learn while building this project? What challenges did you face and how did you overcome them?


In C++, global constructors are executed before ```main()```


## Usage/Examples
---
Run the program using the run scripts
```bash
./build-tools/run.sh
```

Then display the data visually
```python3
python3 ./build-tools/data-visualization.py
```


## Running Tests
---

To run tests manually

```bash
  ./build-tools/run.sh [argument_file_1.arg] [argument_file_2.arg] ..
```

## Dependencies
---

* Matplotlib might need a gui backend to be installed for it work.
* Benchmark
* Linux environment

## Fixes for common errors
---

**Matplotlib is currently using agg, which is a non-GUI backend...**
---
Solution #1
```bash
  sudo apt-get install python3-tk
```
Solution #2
```bash
  pip install pyqt5
```
### Note:
* Usually this error appears when you pip install matplotlib and you are trying to display a plot in a GUI window and you do not have a python module for GUI display.
* The authors of ```matplotlib``` made the pypi software deps not depend on any GUI backend because some people **need** ```matplotlib``` without any GUI backend.
---