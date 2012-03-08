#
# -*- coding: latin-1 -*-
# Time-stamp: <12/03/08 16:06:03 alexs>

# Per-cpu functions

from pykdump.API import *

# Emulate __get_cpu_var. For efficiency rerasons We return
# the whole array (list) of addresses for all CPUs

def get_cpu_var_26(varname):
    if (isinstance(varname, str)):
        cpuvarname = "per_cpu__" + varname
        saddr = sym2addr(cpuvarname)
    else:
        saddr = varname
    
    addrlist = []
    #print CPUS, per_cpu_offsets
    for cpu in range(CPUS):
        addr = (saddr + per_cpu_offsets[cpu])  & long(0xffffffffffffffff)
        addrlist.append(addr)
    return addrlist

def get_cpu_var_26_new(varname):
    if (isinstance(varname, str)):
        cpuvarname = varname
        saddr = sym2addr(cpuvarname)
    else:
        saddr = varname
    addrlist = []
    #print CPUS, per_cpu_offsets
    for cpu in range(CPUS):
        addr = (saddr + per_cpu_offsets[cpu])  & long(0xffffffffffffffff)
        addrlist.append(addr)
    return addrlist

def get_cpu_var_24(varname, cpu = None):
    if (isinstance(varname, str)):
        saddr = sym2addr(varname)
    else:
        saddr = varname
    addrlist = []
    ctype =  whatis(varname).ctype
    ssize = struct_size(ctype)
    addrlist = []
    for cpu in range(CPUS):
        addrlist.append(saddr +  ssize*cpu)
    return addrlist

def get_cpu_var_type(varname):
    if (get_cpu_var ==  get_cpu_var_26):
        varname = "per_cpu__" + varname
    return whatis(varname).ctype

#define __percpu_disguise(pdata) (struct percpu_data *)~(unsigned long)(pdata)
def __percpu_disguise(pdata):
    return ((~pdata) & pointermask)
    
#({                                                        \
#        struct percpu_data *__p = __percpu_disguise(ptr); \
#        (__typeof__(ptr))__p->ptrs[(cpu)];               \
#})

# On 2.6.27 instead of NR_CPU sized array we have ptrs[1]:

# struct percpu_data {
#       void *ptrs[1];
# };

# On 2.6.31 we can configure CONFIG_HAVE_DYNAMIC_PER_CPU_AREA

#extern unsigned long __per_cpu_offset[NR_CPUS];
#define per_cpu_offset(x) (__per_cpu_offset[x])
#define per_cpu_ptr(ptr, cpu)   SHIFT_PERCPU_PTR((ptr), per_cpu_offset((cpu)))
#define SHIFT_PERCPU_PTR(__p, __offset) RELOC_HIDE((__p), (__offset))


def get_percpu_ptr_26_dynamic(ptr, cpu):
    addr = long(ptr) + per_cpu_offsets[cpu]
    if (isinstance(ptr, pykdump.wrapcrash.StructResult)):
        optr = readSU(ptr.PYT_symbol, addr)
    else:
        optr = tPtr(addr, ptr.ptype)
    return optr



# Until we unify tPtr and StructResult


def get_percpu_ptr_26(ptr, cpu):
    p =  __percpu_disguise(ptr)
    #print " ptr=0x%x disguised = 0x%x" % (ptr, p)
    dp = readSU("struct percpu_data", p)
    if (isinstance(ptr, pykdump.wrapcrash.StructResult)):
        optr = readSU(ptr.PYT_symbol, dp.ptrs[cpu])
    else:
        optr = tPtr(dp.ptrs[cpu], ptr.ptype)
    return optr


def percpu_counter_sum(fbc):
    count = fbc.count

    try:
        counters = fbc.counters
    except KeyError:
        return count
    for cpu in range(sys_info.CPUS):
        #count = Deref(percpu_ptr(counters, cpu))
        count += readS32(percpu_ptr(counters, cpu))
        #print cpu, count
    return count


    
CPUS = sys_info.CPUS
pointermask = sys_info.pointermask

if (symbol_exists("per_cpu__runqueues")):
    pda_addr = None
    if (symbol_exists("cpu_pda")):
        # AMD64, older kernels.
        # struct x8664_pda cpu_pda[NR_CPUS] __cacheline_aligned; 
        pda_addr = sym2addr("cpu_pda")
        
        per_cpu_offsets = []
        size = struct_size("struct x8664_pda")
        for cpu in range(0, sys_info.CPUS):
            cpu_pda = readSU("struct x8664_pda", pda_addr +  size*cpu)
            offset = cpu_pda.data_offset
            per_cpu_offsets.append(offset)
 
    elif(symbol_exists("_cpu_pda") and not symbol_exists("__per_cpu_offset")):
        # This symbol exists both on AMD64 (newer kernels) and I386,
        # but on I386 it does not contain offsets...
        # extern struct x8664_pda *_cpu_pda[];
        # struct i386_pda *_cpu_pda[8];

        pda_ptr_arr = readSymbol("_cpu_pda")

        per_cpu_offsets = []
        for cpu in range(0, sys_info.CPUS):
            offset = pda_ptr_arr[cpu].Deref.data_offset
            per_cpu_offsets.append(offset)
    elif (symbol_exists("__per_cpu_offset")):
        per_cpu_offsets = readSymbol("__per_cpu_offset")
    else:
        per_cpu_offsets = [0]

    
    get_cpu_var = get_cpu_var_26
    if (struct_exists("struct percpu_data")):
        percpu_ptr = get_percpu_ptr_26
    else:
        percpu_ptr = get_percpu_ptr_26_dynamic

elif (symbol_exists("runqueues")):
    # Either 2.4 _or_ 2.6.35+ :-)
    if (symbol_exists("percpu_counters")):
        # 2.6.35+
        per_cpu_offsets = readSymbol("__per_cpu_offset")
        get_cpu_var = get_cpu_var_26_new
        percpu_ptr = get_percpu_ptr_26_dynamic
    else:
        # 2.4
        get_cpu_var = get_cpu_var_24
        percpu_ptr = None
else:
    raise TypeError("Cannot process runqueues on this kernel")
