import os
import mmap

def probe_mem(pid):
    maps = file("/proc/" + str(pid) + "/maps").read()
    
    stack = []
    wx = []
    
    for row in maps.split("\n"):
        elts = row.split(" ")
        if len(elts) < 5:
            continue
        ranges = elts[0]
        perms = elts[1]

        
        
        # find executable and writable memory and the stack
        if perms[1] == 'w' and perms[2] == 'x':
            wx.append(ranges)
        if elts[-1].find("[stack]") != -1:
            stack.append(ranges)

    return (wx, stack)


def extract_mem(pid, regions):
    fname = "/proc/" + str(pid) + "/mem"
    memfd = os.open(fname, 0)
    for elt in regions:
        ss = elt.split("-")
        region_start = int(ss[0], 16)
        region_end = int(ss[1], 16)
    
        print hex(region_start), hex(region_end - region_start)
        mm = mmap.mmap(memfd, 0, offset=region_start)
    os.close(memfd)
    
        
        
if __name__ == "__main__":
    ppid = os.getpid()
    (wx,stack) = probe_mem(ppid)
    print extract_mem(ppid, wx)
    print extract_mem(ppid, stack)
    exit(0)
    
    pids = os.listdir("/proc")
    
    for proc in pids:
        try:
            f = int(proc)
            (wx, stack) = probe_mem(f)
            if len(wx) + len(stack) > 0:
                print pid, wx, stack
        except:
            pass
        
    
