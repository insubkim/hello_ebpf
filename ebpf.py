#!/usr/bin/python3
from bcc import BPF

# 1. eBPF 프로그램 (C언어)
# kprobe__sys_execve : sys_execve 함수가 호출될 때 이 함수를 실행해라!
prog = """
int kprobe__sys_execve(void *ctx) {
    bpf_trace_printk("Hello, World! New Process Detected!\\n");
    return 0;
}
"""

# 2. 커널에 로드 및 어태치
b = BPF(text=prog)

print("Monitoring execve()... Ctrl-C to stop.")

# 3. 로그 읽기
while True:
    try:
        # 커널의 파이프(/sys/kernel/debug/tracing/trace_pipe)에서 로그를 가져옴
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print("%s (PID: %d): %s" % (task, pid, msg))
    except KeyboardInterrupt:
        exit()
