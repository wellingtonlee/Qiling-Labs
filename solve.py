# Solutions to QilingLabs: https://www.shielder.com/blog/2021/07/qilinglab-release/
# Using qiling == 1.4.2 and Python 3.9.12
from qiling import *
from qiling.const import *
from qiling.os.const import INT
from qiling.os.mapper import QlFsMappedObject 

def my_syscall_uname(ql, address, params):
    ql.mem.write(address + (65*3), b'ChallengeStart')

class Fake_urandom(QlFsMappedObject):
    def read(self, size):
        if size == 1:
            return b'\x00'
        return b'\x01'*size

    def fstat(self):
        return -1

    def close(self):
        return 0

class Fake_cmdline(QlFsMappedObject):
    def read(self, size):
        return b'qilinglab'

    def fstat(self):
        return -1

    def close(self):
        return 0

def my_syscall_getrandom(ql, buf, count, flags, _):
    ql.mem.write(buf, b'\x01'*count)

def dump(ql: Qiling, *args, **kwargs) -> None:
    ql.reg.x0 = 1

def my_api_rand(ql, *args, **kwargs):
    ql.reg.x0 = 0

def chal6_hook(ql, *args, **kwargs) -> None:
    ql.reg.x0 = 0

def my_sleep(ql, *args, **kwargs) -> None:
    ql.reg.x0 = 0

def chal8_hook(ql, *args, **kwargs) -> None:
    ql.mem.write(ql.reg.x1, ql.pack64(1))

def my_lower(ql, *args, **kwargs) -> None:
    params = ql.os.resolve_fcall_params({'c': INT})
    ql.reg.x0 = params['c']

def chal11_hook(ql, *args, **kwargs) -> None:
    ql.reg.x0 = 0x1337<<0x10

def my_sandbox(path, rootfs):
    # setup Qiling engine
    ql = Qiling(path, rootfs)
    ql.verbose = QL_VERBOSE.OFF
    
    addr = 0x1337
    ql.mem.map(addr//4096*4096, 4096)
    ql.mem.write(0x1337, b'\x39\x05')

    # Challenge 2
    ql.os.set_syscall("uname", my_syscall_uname, QL_INTERCEPT.EXIT)

    # Challenge 3
    ql.add_fs_mapper("/dev/urandom", Fake_urandom())
    ql.os.set_syscall("getrandom", my_syscall_getrandom, QL_INTERCEPT.EXIT)

    # Challenge 4
    OFFSET = 0xfe0
    BASE = int(ql.profile.get("OS64", "load_address"), 16)
    ql.hook_address(dump, BASE + OFFSET)

    # Challenge 5
    ql.set_api("rand", my_api_rand)

    # Challenge 6
    ql.hook_address(chal6_hook, BASE + 0x1118)

    # Challenge 7
    ql.set_api("sleep", my_sleep)

    # Challenge 8
    ql.hook_address(chal8_hook, BASE + 0x11dc)

    # Challenge 9
    ql.set_api("tolower", my_lower)

    # Challenge 10
    ql.add_fs_mapper("/proc/self/cmdline", Fake_cmdline())

    # Challenge 11
    ql.hook_address(chal11_hook, BASE + 0x13f0)

    ql.run()

if __name__ == "__main__":
    # execute binary under our rootfs
    my_sandbox(["qilinglab-aarch64"], "aarch64_rootfs")
