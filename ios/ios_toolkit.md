# iOS Toolkit

### CydiaSubstrate

Is the infrastructure of most tweaks. It consists of MobileHooker, MobileLoader and Safe mode.

##### Mobile Hooker

is used to replace system calls, or namely, hook. There are two major functions: 

```objective-c
void MSHookMessageEx(Class class, SEL selector, IMP replacement, IMP *result);
void MSHookFunction(void* function, void* replacement, void** p_original);
```

MSHookMessageEx works on Objective-C methods. It calls method_setImplementation to replace the original implementation of [class selector] with “replacement”.

MSHookFunction is used for C/C++ hooks, and works in assembly level. Conceptually,
when the process is about to call “function”, MSHookFunction makes it execute “replacement” instead, and allocate some memory to store the original “function” and its return address, making it possible for the process to execute “function” optionally, and guarantees the process can run as usual after executing “replacement”.

##### Example Hooking

1. 

```bash
#Create iOSRETargetApp with Theos
snakeninnys-MacBook:Code snakeninny$ /opt/theos/bin/nic.pl
NIC 2.0 - New Instance Creator
------------------------------
[1.] iphone/application
[2.] iphone/library
[3.] iphone/preference_bundle
[4.] iphone/tool
[5.] iphone/tweak
Choose a Template (required): 1
Project Name (required): iOSRETargetApp
Package Name [com.yourcompany.iosretargetapp]: com.iosre.iosretargetapp
Author/Maintainer Name [snakeninny]: snakeninny
Instantiating iphone/application in iosretargetapp/...
Done.
```

2. Modify RootViewController.mm as follows

```objective-c
#import "RootViewController.h"
class CPPClass
{
public:
void CPPFunction(const char *);
};
void CPPClass::CPPFunction(const char *arg0)
{
for (int i = 0; i < 66; i++) // This for loop makes this function long enough to
validate MSHookFunction
{
u_int32_t randomNumber;
if (i % 3 == 0) randomNumber = arc4random_uniform(i);
NSProcessInfo *processInfo = [NSProcessInfo processInfo];
NSString *hostName = processInfo.hostName;
int pid = processInfo.processIdentifier;
NSString *globallyUniqueString = processInfo.globallyUniqueString;
NSString *processName = processInfo.processName;
NSArray *junks = @[hostName, globallyUniqueString, processName];
NSString *junk = @"";
for (int j = 0; j < pid; j++)
{
if (pid % 6 == 0) junk = junks[j % 3];
}
if (i % 68 == 1) NSLog(@"Junk: %@", junk);
}
NSLog(@"iOSRE: CPPFunction: %s", arg0);
}
extern "C" void CFunction(const char *arg0)
{
for (int i = 0; i < 66; i++) // This for loop makes this function long enough to
validate MSHookFunction
    {
u_int32_t randomNumber;
if (i % 3 == 0) randomNumber = arc4random_uniform(i);
NSProcessInfo *processInfo = [NSProcessInfo processInfo];
NSString *hostName = processInfo.hostName;
int pid = processInfo.processIdentifier;
NSString *globallyUniqueString = processInfo.globallyUniqueString;
NSString *processName = processInfo.processName;
NSArray *junks = @[hostName, globallyUniqueString, processName];
NSString *junk = @"";
for (int j = 0; j < pid; j++)
{
if (pid % 6 == 0) junk = junks[j % 3];
}
if (i % 68 == 1) NSLog(@"Junk: %@", junk);
}
NSLog(@"iOSRE: CFunction: %s", arg0);
}
extern "C" void ShortCFunction(const char *arg0) // ShortCFunction is too short to be
hooked
{
CPPClass cppClass;
cppClass.CPPFunction(arg0);
}
@implementation RootViewController
- (void)loadView {
self.view = [[[UIView alloc] initWithFrame:[[UIScreen mainScreen]
applicationFrame]] autorelease];
self.view.backgroundColor = [UIColor redColor];
}
- (void)viewDidLoad
{
[super viewDidLoad];
CPPClass cppClass;
cppClass.CPPFunction("This is a C++ function!");
CFunction("This is a C function!");
ShortCFunction("This is a short C function!");
}
@end
```

3. Modify Makefile & install tweak:

```objective-c
export THEOS_DEVICE_IP = iOSIP
export ARCHS = armv7 arm64
export TARGET = iphone:clang:latest:8.0
include theos/makefiles/common.mk
APPLICATION_NAME = iOSRETargetApp
iOSRETargetApp_FILES = main.m iOSRETargetAppApplication.mm RootViewController.mm
iOSRETargetApp_FRAMEWORKS = UIKit CoreGraphics
include $(THEOS_MAKE_PATH)/application.mk
after-install::
install.exec "su mobile -c uicache"
```

In the above code, “su mobile - C uicache” is used to refresh the UI cache of SpringBoard so that iOSRETargetApp’s icon can be shown on SpringBoard. Run “make package install” in Terminal to install this tweak on the device. Launch iOSRETargetApp, ssh into iOS after the red background shows, and see whether it outputs as expected:

```bash
FunMaker-5:~ root# grep iOSRE: /var/log/syslog
Nov 18 11:13:34 FunMaker-5 iOSRETargetApp[5072]: iOSRE: CPPFunction: This is a C++
function!
Nov 18 11:13:34 FunMaker-5 iOSRETargetApp[5072]: iOSRE: CFunction: This is a C function!
Nov 18 11:13:35 FunMaker-5 iOSRETargetApp[5072]: iOSRE: CPPFunction: This is a short C
function!
```

4. Create iOSREHookerTweak with Theos:

```bash
snakeninnys-MacBook:Code snakeninny$ /opt/theos/bin/nic.pl
NIC 2.0 - New Instance Creator
------------------------------
[1.] iphone/application
[2.] iphone/library
[3.] iphone/preference_bundle
[4.] iphone/tool
[5.] iphone/tweak
Choose a Template (required): 5
Project Name (required): iOSREHookerTweak
Package Name [com.yourcompany.iosrehookertweak]: com.iosre.iosrehookertweak
Author/Maintainer Name [snakeninny]: snakeninny
[iphone/tweak] MobileSubstrate Bundle filter [com.apple.springboard]:
com.iosre.iosretargetapp
[iphone/tweak] List of applications to terminate upon installation (space-separated, '-'
for none) [SpringBoard]: iOSRETargetApp
Instantiating iphone/tweak in iosrehookertweak/...
Done.
```

5. Modify Tweak.xm

```objective-c
#import <substrate.h>
void (*old__ZN8CPPClass11CPPFunctionEPKc)(void *, const char *);
void new__ZN8CPPClass11CPPFunctionEPKc(void *hiddenThis, const char *arg0)
{
if (strcmp(arg0, "This is a short C function!") == 0)
old__ZN8CPPClass11CPPFunctionEPKc(hiddenThis, "This is a hijacked short C function from
new__ZN8CPPClass11CPPFunctionEPKc!");
	else old__ZN8CPPClass11CPPFunctionEPKc(hiddenThis, "This is a hijacked C++
function!");
}
void (*old_CFunction)(const char *);
void new_CFunction(const char *arg0)
{
old_CFunction("This is a hijacked C function!"); // Call the original CFunction
}
void (*old_ShortCFunction)(const char *);
void new_ShortCFunction(const char *arg0)
{
old_CFunction("This is a hijacked short C function from new_ShortCFunction!"); //
Call the original ShortCFunction
}
%ctor
{
@autoreleasepool
{
MSImageRef image =
MSGetImageByName("/Applications/iOSRETargetApp.app/iOSRETargetApp");
void *__ZN8CPPClass11CPPFunctionEPKc = MSFindSymbol(image,
"__ZN8CPPClass11CPPFunctionEPKc");
if (__ZN8CPPClass11CPPFunctionEPKc) NSLog(@"iOSRE: Found CPPFunction!");
MSHookFunction((void *)__ZN8CPPClass11CPPFunctionEPKc, (void
*)&new__ZN8CPPClass11CPPFunctionEPKc, (void **)&old__ZN8CPPClass11CPPFunctionEPKc);
void *_CFunction = MSFindSymbol(image, "_CFunction");
if (_CFunction) NSLog(@"iOSRE: Found CFunction!");
MSHookFunction((void *)_CFunction, (void *)&new_CFunction, (void
**)&old_CFunction);
void *_ShortCFunction = MSFindSymbol(image, "_ShortCFunction");
if (_ShortCFunction) NSLog(@"iOSRE: Found ShortCFunction!");
MSHookFunction((void *)_ShortCFunction, (void *)&new_ShortCFunction, (void
**)&old_ShortCFunction); // This MSHookFuntion will fail because ShortCFunction is too
short to be hooked
}
}                    
```



The 3 parameters of MSHookFunction are: the original function to be hooked/replaced, the replacement function, and the original function saved by MobileHooker. Just like Sherlock Holmes needs Dr. Watson’s assistance, MSHookFunction doesn’t work alone, it only functions with a conventional writing pattern, shown as follows:

```objective-c
#import <substrate.h>
returnType (*old_symbol)(args);
returnType new_symbol(args)
{
// Whatever
}
void InitializeMSHookFunction(void) // This function is often called in %ctor i.e.
constructor
{
MSImageRef image =
MSGetImageByName("/path/to/binary/who/contains/the/implementation/of/symbol");
void *symbol = MSFindSymbol(image, "symbol");
if (symbol) MSHookFunction((void *)symbol, (void *)&new_ symbol, (void **)&old_
symbol);
else NSLog(@"Symbol not found!");
}
```



6. Modify Makefile and install the tweak

   ```bash
   export THEOS_DEVICE_IP = iOSIP
   export ARCHS = armv7 arm64
   export TARGET = iphone:clang:latest:8.0
   include theos/makefiles/common.mk
   TWEAK_NAME = iOSREHookerTweak
   iOSREHookerTweak_FILES = Tweak.xm
   include $(THEOS_MAKE_PATH)/tweak.mk
   after-install::
   install.exec "killall -9 iOSRETargetApp"
   ```

   iOS crashes when tweak sucks. A tweak is essentially a dylib residing in another process, once something goes wrong in it, the entire process crashes. If it unfortunately happens to be SpringBoard or other system processes, tweak crash leads to a system paralysis.



### LLDB & Debugserver

2 most commonly used scenarios of debugserver are process launching and attaching. Both possess very simple commands:

```bash
debugserver -x backboard IP:port /path/to/executable
```

debugserver will launch the specific executable and open the specific port, then wait for LLDB’s connection from IP. debugserver will attach to process with the name “ProcessName” and open the specific port, then wait for LLDB’s connection from IP.
For example:

```bash
FunMaker-5:~ root# debugserver -x backboard *:1234 /Applications/MobileSMS.app/MobileSMS
debugserver-@(#)PROGRAM:debugserver PROJECT:debugserver-320.2.89
for armv7.
Listening to port 1234 for a connection from *...
```

The above command will launch MobileSMS and open port 1234, then wait for LLDB’s
connection from any IP. And for the following command:

```bash
FunMaker-5:~ root# debugserver 192.168.1.6:1234 -a "MobileSMS"
debugserver-@(#)PROGRAM:debugserver PROJECT:debugserver-320.2.89
for armv7.
Attaching to process MobileNotes...
Listening to port 1234 for a connection from 192.168.1.6...
```

debugserver will attach to MobileSMS and open port 1234, then wait for LLDB’s connection from 192.168.1.6.



#### LLDB

```bash
snakeninnysiMac:~ snakeninny$ /Applications/OldXcode.app/Contents/Developer/usr/bin/lldb

(lldb) process connect connect://iOSIP:1234
Process 790987 stopped
* thread #1: tid = 0xc11cb, 0x3995b4f0 libsystem_kernel.dylib`mach_msg_trap + 20, queue
= 'com.apple.main-thread, stop reason = signal SIGSTOP
frame #0: 0x3995b4f0 libsystem_kernel.dylib`mach_msg_trap + 20
libsystem_kernel.dylib`mach_msg_trap + 20:
-> 0x3995b4f0: pop {r4, r5, r6, r8}
0x3995b4f4: bx lr
libsystem_kernel.dylib`mach_msg_overwrite_trap:
0x3995b4f8: mov r12, sp
0x3995b4fc: push {r4, r5, r6, r8}
```

Note, the execution of “process connect connect://iOSIP:1234” will take a rather long time (approximately more than 3 minutes in a WiFi environment) to connect to debugserver, please be patient.

**<u>Commands:</u>**

- “`image list`” is similar to “info shared” in GDB, which is used to list the main executable and all dependent libraries (hereinafter referred to as images) in the debugged process. Because of ASLR (Address Space Layout Randomization, see http://theiphonewiki.com/wiki/ASLR), every time the process launches, a random offset will be added to the starting address of all
  images in that process, making their virtual memory addresses hard to predict.
- “`breakpoint`” is similar to “break” in GDB, it’s used to set breakpoints.

```bash
#function breakpoint
(lldb) b NSLog

#addresses
(lldb) br s -a 0xCCCCC
#Breakpoint 6: address = 0x0000000f
(lldb) br s -a '0x6+0x9'
```



Finding ASLR offset in LLDB:

- ssh into iOS to run debugserver with the following commands:

  ```bash
  snakeninnysiMac:~ snakeninny$ ssh root@iOSIP
  FunMaker-5:~ root# debugserver *:1234 -a "SpringBoard"
  debugserver-@(#)PROGRAM:debugserver PROJECT:debugserver-320.2.89
  for armv7.
  Attaching to process SpringBoard...
  Listening to port 1234 for a connection from *...
  ```

- Then connect to debugserver with LLDB on OSX, and find the ASLR offset:

  ```bash
  snakeninnysiMac:~ snakeninny$ /Applications/OldXcode.app/Contents/Developer/usr/bin/lldb
  (lldb) process connect connect://iOSIP:1234
  Process 93770 stopped
  * thread #1: tid = 0x16e4a, 0x30dee4f0 libsystem_kernel.dylib`mach_msg_trap + 20, queue
  = 'com.apple.main-thread, stop reason = signal SIGSTOP
  frame #0: 0x30dee4f0 libsystem_kernel.dylib`mach_msg_trap + 20
  libsystem_kernel.dylib`mach_msg_trap + 20:
  -> 0x30dee4f0: pop {r4, r5, r6, r8}
  0x30dee4f4: bx lr
  libsystem_kernel.dylib`mach_msg_overwrite_trap:
  0x30dee4f8: mov r12, sp
  0x30dee4fc: push {r4, r5, r6, r8}
  (lldb) image list -o -f
  [ 0] 0x000b5000
  /System/Library/CoreServices/SpringBoard.app/SpringBoard(0x00000000000b9000)
  [ 1] 0x006ea000 /Library/MobileSubstrate/MobileSubstrate.dylib(0x00000000006ea000)
  [ 2] 0x01645000
  /System/Library/PrivateFrameworks/StoreServices.framework/StoreServices(0x000000002ca700
  00)
  [ 3] 0x01645000
  /System/Library/PrivateFrameworks/AirTraffic.framework/AirTraffic(0x0000000027783000)
  ……
  [419] 0x00041000 /usr/lib/dyld(0x000000001fe41000)
  (lldb) c
  Process 93770 resuming
  ```

  The ASLR offset of SpringBoard is 0xb5000.

  

- Set and trigger the breakpoint. So the base address with offset of the first instruction is 0x17730 + 0xb5000 = 0xCC730.
  Input “br s -a 0xCC730” in LLDB to set a breakpoint on the first instruction:

```bash
(lldb) br s -a 0xCC730
Breakpoint 1: where = SpringBoard`___lldb_unnamed_function299$$SpringBoard, address =
0x000cc730
```

Then press the home button to trigger the breakpoint:

```bash
(lldb) br s -a 0xCC730
Breakpoint 1: where = SpringBoard`___lldb_unnamed_function299$$SpringBoard, address =
0x000cc730
Process 93770 stopped
* thread #1: tid = 0x16e4a, 0x000cc730
SpringBoard`___lldb_unnamed_function299$$SpringBoard, queue = 'com.apple.main-thread,
stop reason = breakpoint 1.1
frame #0: 0x000cc730 SpringBoard`___lldb_unnamed_function299$$SpringBoard
SpringBoard`___lldb_unnamed_function299$$SpringBoard:
-> 0xcc730: push {r4, r5, r6, r7, lr}
0xcc732: add r7, sp, #12
0xcc734: push.w {r8, r10, r11}
0xcc738: sub sp, #80
(lldb) p (char *)$r1
(char *) $0 = 0x0042f774 "_menuButtonDown:"
```

When the process stops, you can use “c” command to “continue” (running) the process.

You can also use commands like “br dis”, “br en” and “br del” to disable, enable and delete breakpoints. The command to disable all breakpoints is as follows:

```bash
(lldb) br dis
All breakpoints disabled. (2 breakpoints)

(lldb) br dis 6
1 breakpoints disabled.

(lldb) br en
All breakpoints enabled. (2 breakpoints)

(lldb) br en 6
1 breakpoints enabled.

(lldb) br del
About to delete all breakpoints, do you want to do that?: [Y/n] Y

(lldb) br del 8
1 breakpoints deleted; 0 breakpoint locations disabled.
```

- Printing:

  The base address with offset of “MOVS R6, #0” is known to be 0xE37DE, let’s set a
  breakpoint on it and print R6’s value when we hit the breakpoint:

```bash
(lldb) br s -a 0xE37DE
Breakpoint 2: where = SpringBoard`___lldb_unnamed_function299$$SpringBoard + 174,
address = 0x000e37de
Process 99787 stopped
* thread #1: tid = 0x185cb, 0x000e37de
SpringBoard`___lldb_unnamed_function299$$SpringBoard + 174, queue = 'com.apple.mainthread,
stop reason = breakpoint 2.1
frame #0: 0x000e37de SpringBoard`___lldb_unnamed_function299$$SpringBoard + 174
SpringBoard`___lldb_unnamed_function299$$SpringBoard + 174:
-> 0xe37de: movs r6, #0
0xe37e0: movt r0, #75
0xe37e4: movs r1, #1
0xe37e6: add r0, pc
(lldb) p $r6
(unsigned int) $1 = 364526080

(lldb) ni
Process 99787 stopped
* thread #1: tid = 0x185cb, 0x000e37e0
SpringBoard`___lldb_unnamed_function299$$SpringBoard + 176, queue = 'com.apple.mainthread,
stop reason = instruction step over
frame #0: 0x000e37e0 SpringBoard`___lldb_unnamed_function299$$SpringBoard + 176
SpringBoard`___lldb_unnamed_function299$$SpringBoard + 176:
-> 0xe37e0: movt r0, #75
0xe37e4: movs r1, #1
0xe37e6: add r0, pc
0xe37e8: cmp r5, #0
(lldb) p $r6
(unsigned int) $2 = 0
(lldb) c
Process 99787 resuming
```



- nexti and stepi

  Both of “nexti” and “stepi” are used to execute the next instruction, but the biggest
  difference between them is that the former does not go/step inside a function but the latter does. They are two of the most used commands, and can be abbreviated as “ni” and “si” respectively.



- register write

  “register write” is used to write a specific value to a specific register, hence “modify the program when it stops, and observe the modification of its execution flow”.

```bash
Process 731 stopped
* thread #1: tid = 0x02db, 0x000ee7a2
SpringBoard`___lldb_unnamed_function299$$SpringBoard + 114, queue = ‘com.apple.mainthread,
stop reason = breakpoint 3.1
frame #0: 0x000ee7a2 SpringBoard`___lldb_unnamed_function299$$SpringBoard + 114
SpringBoard`___lldb_unnamed_function299$$SpringBoard + 114:
-> 0xee7a2: tst.w r0, #255
0xee7a6: bne 0xee7b2 ; ___lldb_unnamed_function299$$SpringBoard
+ 130
0xee7a8: bl 0x10d340 ;
___lldb_unnamed_function1110$$SpringBoard
0xee7ac: tst.w r0, #255
(lldb) p $r0
(unsigned int) $5 = 0
(lldb) register write r0 1
(lldb) p $r0
(unsigned int) $6 = 1
(lldb) ni
```

### Dumpdecrypted

When introducing class-dump, we’ve mentioned that Apple encrypts all Apps from
AppStore, protecting them from being class-dumped. If we want to class-dump StoreApps, we have to decrypt their executables at first. A handy tool, dumpdecrypted, by Stefan Esser (@i0n1c) is commonly used in iOS reverse engineering.

```bash
#download source
snakeninnysiMac:~ snakeninny$ cd /Users/snakeninny/Code/
snakeninnysiMac:Code snakeninny$ git clone git://github.com/stefanesser/dumpdecrypted/
Cloning into ‘dumpdecrypted’...
remote: Counting objects: 31, done.
remote: Total 31 (delta 0), reused 0 (delta 0)
Receiving objects: 100% (31/31), 6.50 KiB | 0 bytes/s, done.
Resolving deltas: 100% (15/15), done.
Checking connectivity... done

#Compile the source code and get dumpdecrypted.dylib
snakeninnysiMac:~ snakeninny$ cd /Users/snakeninny/Code/dumpdecrypted/
snakeninnysiMac:dumpdecrypted snakeninny$ make
`xcrun --sdk iphoneos --find gcc` -Os -Wimplicit -isysroot `xcrun --sdk iphoneos --
show-sdk-path` -F`xcrun --sdk iphoneos --show-sdk-path`/System/Library/Frameworks -
F`xcrun --sdk iphoneos --show-sdk-path`/System/Library/PrivateFrameworks -arch armv7 -
arch armv7s -arch arm64 -c -o dumpdecrypted.o dumpdecrypted.c
`xcrun --sdk iphoneos --find gcc` -Os -Wimplicit -isysroot `xcrun --sdk iphoneos --
show-sdk-path` -F`xcrun --sdk iphoneos --show-sdk-path`/System/Library/Frameworks -
F`xcrun --sdk iphoneos --show-sdk-path`/System/Library/PrivateFrameworks -arch armv7 -
arch armv7s -arch arm64 -dynamiclib -o dumpdecrypted.dylib dumpdecrypted.o

#Locate the executable to be decrypted with “ps” command. First close all StoreApps on iOS, then launch TargetApp and ssh into iOS to print all processes:
snakeninnysiMac:~ snakeninny$ ssh root@iOSIP
FunMaker-5:~ root# ps -e
PID TTY TIME CMD
1 ?? 3:28.32 /sbin/launchd
……
5717 ?? 0:00.21
/System/Library/PrivateFrameworks/MediaServices.framework/Support/mediaartworkd
5905 ?? 0:00.20 sshd: root@ttys000
5909 ?? 0:01.86 /var/mobile/Containers/Bundle/Application/03B61840-2349-4559-
B28E-0E2C6541F879/TargetApp.app/TargetApp
5911 ?? 0:00.07 /System/Library/Frameworks/UIKit.framework/Support/pasteboardd
5907 ttys000 0:00.03 -sh
5913 ttys000 0:00.01 ps –e

#Find out TargetApp’s Documents directory via Cycript
FunMaker-5:~ root# cycript -p TargetApp
cy# [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory
inDomains:NSUserDomainMask][0]
#”file:///var/mobile/Containers/Data/Application/D41C4343-63AA-4BFF-904B-
2146128611EE/Documents/”

#Copy dumpdecrypted.dylib to TargetApp’s Documents directory:
snakeninnysiMac:~ snakeninny$ scp
/Users/snakeninny/Code/dumpdecrypted/dumpdecrypted.dylib
root@iOSIP:/var/mobile/Containers/Data/Application/D41C4343-63AA-4BFF-904B-
2146128611EE/Documents/
dumpdecrypted.dylib
100% 193KB 192.9KB/s 00:00

#start decrypting
FunMaker-5:~ root# cd /var/mobile/Containers/Data/Application/D41C4343-63AA-4BFF-904B-
2146128611EE/Documents/
FunMaker-5:/var/mobile/Containers/Data/Application/D41C4343-63AA-4BFF-904B-
2146128611EE/Documents root# DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib
/var/mobile/Containers/Bundle/Application/03B61840-2349-4559-B28E-
0E2C6541F879/TargetApp.app/TargetApp
mach-o decryption dumper
DISCLAIMER: This tool is only meant for security research purposes, not for application
crackers.
[+] detected 32bit ARM binary in memory.
[+] offset to cryptid found: @0x81a78(from 0x81000) = a78
[+] Found encrypted data at address 00004000 of length 6569984 bytes - type 1.
[+] Opening /private/var/mobile/Containers/Bundle/Application/03B61840-2349-4559-B28E-
0E2C6541F879/TargetApp.app/TargetApp for reading.
[+] Reading header
[+] Detecting header type
[+] Executable is a plain MACH-O image
[+] Opening TargetApp.decrypted for writing.
[+] Copying the not encrypted start of the file
[+] Dumping the decrypted data into the file
[+] Copying the not encrypted remainder of the file
[+] Setting the LC_ENCRYPTION_INFO->cryptid to 0 at offset a78
[+] Closing original file
```

Copy TargetApp.decrypted to OSX ASAP. class-dump and IDA have been waiting for ages!