import os, signal, sys, time

def report(label):
    size=os.get_terminal_size(0)
    print(label, os.isatty(0), os.isatty(1), size.lines, size.columns, flush=True)
report('INITIAL')
signal.signal(signal.SIGWINCH, lambda *_: report('RESIZED'))
for line in sys.stdin:
    if line.strip()=='quit': break
