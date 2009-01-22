#
# -*- coding: latin-1 -*-
# Time-stamp: <08/12/10 14:39:40 alexs>

# Per-cpu functions

from pykdump.API import *

# Emulate __get_cpu_var. For efficiency rerasons We return
# the whole array (list) of addresses for all CPUs

def get_cpu_var_26(varname):
    cpuvarname = "per_cpu__" + varname
    saddr = sym2addr(cpuvarname)
    addrlist = []
    #print CPUS, per_cpu_offsets
    for cpu in range(CPUS):
        addr = (saddr + per_cpu_offsets[cpu])  & 0xffffffffffffffffL
        addrlist.append(addr)
    return addrlist

def get_cpu_var_24(varname, cpu = None):
    saddr = sym2addr(varname)
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
#        (__typeof__(ptr))__p->ptrs[(cpu)];	          \
#})

# On 2.6.27 instead of NR_CPU sized array we have ptrs[1]:

# struct percpu_data {
# 	void *ptrs[1];
# };


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
    percpu_ptr = get_percpu_ptr_26
else:
    get_cpu_var = get_cpu_var_24
    percpu_ptr = None
