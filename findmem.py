import os
import mmap
import traceback

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
    memfd = open(fname, "r", 0)
    for elt in regions:
        ss = elt.split("-")
        region_start = int(ss[0], 16)
        region_end = int(ss[1], 16)
        print elt
        print hex(region_start), hex(region_end - region_start)
        memfd.seek(region_start)
        data = memfd.read(region_end - region_start)
        print hex(len(data))

    memfd.close()



if __name__ == "__main__":
    pids = os.listdir("/proc")

    for proc in pids:
        try:
            f = int(proc)
            psname = os.readlink("/proc/" + proc + "/exe")

            (wx, stack) = probe_mem(f)
            if wx != []:
                print proc, psname, wx, stack
        except:
            # traceback.print_exc()
            pass



