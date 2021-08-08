# GDB Gef

**<u>Installation:</u>**

```bash
# via the install script
$ wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh

# manually
$ wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
$ echo source ~/.gdbinit-gef.py >> ~/.gdbinit
```

```bash
Alternatively from inside gdb directly:

$ gdb -q
(gdb) pi \
import urllib.request as u, tempfile as t; \
g=t.NamedTemporaryFile(suffix='-gef.py'); \
open(g.name, 'wb+').write( u.urlopen('https://github.com/hugsy/gef/raw/master/gef.py').read() ); \
gdb.execute('source %s' % g.name)
```

**<u>Run</u>**:

Then just start playing (for local files):

```bash
$ gdb -q /path/to/my/bin
gef➤  gef help
```

Or (for remote debugging):

```bash
remote:~ $ gdbserver 0.0.0.0:1234 /path/to/file
Running as PID: 666
```

And:

```bash
local:~ $ gdb -q
gef➤  gef-remote -t your.ip.address:1234 -p 666
```



### Go-to Commands

```bash
elf-info
checksec
set architecture
set disassembly flavor intel

start #will break at the entry to start
uf _start #dump assembly for _start function

vmmap
xinfo $pc #display info of program counter, swap with location of choice

telescope $esp l30 #recursive dereference the location given to find final value

b *0xhex_address
b main

x/s $variable/address
ni 

x/wx $esp
```



### Exploit specific debugging

```bash
pattern create <number>

pattern search $esp

!git clone https://github.com/hugsy/gef-scripts
gef config gef.extra_plugins_dir "<location of repo>"
gef save

skel remote=chall.address.com:port_num

format-string-helper #sets automatic breakpoints at insecure print calls

gef config heap-analysis-helper.check_uaf
heap-analysis-helper #sets auto breakpoints for heap issues
```

