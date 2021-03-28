# Theories

### Objective-C

Almost all popular software in Cydia are various creative tweaks (A tweak icon is shown in figure 5-1), such as Activator, Barrel, SwipeSelection, etc. Generally speaking, the core of a tweak is a variety of hooks and most hooks target Objective-C methods.

Objective-C is a typical object-oriented programming language; iOS consists of many small components and each component is an object. For example, every single icon, message and photo is an object. Besides these visible objects, there are also many objects working in the background, providing a variety of support for foreground objects. For instance, some objects are responsible for communicating with servers of Apple and some others are responsible for reading and writing files.

Generally speaking, we use C, C++ and Objective-C to write a tweak. When we have an idea, how can we manage to turn it into a useful tweak?

Objective-C methods follow a regular naming convention, making it possible for us to guess the meanings of most methods. For example, in SpringBoard.h:

```bash
- (void)reboot;
- (void)relaunchSpringBoard;
```



And in UIViewController.h:

```bash
- (void)attentionClassDumpUser:(id)arg1
yesItsUsAgain:(id)arg2
althoughSwizzlingAndOverridingPrivateMethodsIsFun:(id)arg3
itWasntMuchFunWhenYourAppStoppedWorking:(id)arg4
pleaseRefrainFromDoingSoInTheFutureOkayThanksBye:(id)arg5;
```



### Locate Target Files

After we know what functions we want to implement, we should start to look for the
binaries that provide these functions. In general, the most frequently used methods to locate the binaries are as follows.

#### Locate Target Files

After we know what functions we want to implement, we should start to look for the
binaries that provide these functions. In general, the most frequently used methods to locate the binaries are as follows.

- **<u>Fixed location:</u>** At this stage, our targets of reverse engineering are usually dylibs, bundles and daemons. Fortunately, the locations of these files are almost fixed in the filesystem.

  - CydiaSubstrate based dylibs are all stored in  “/Library/MobileSubstrate/DynamicLibraries/”. We can find them without effort.

  - Bundles can be divided into 2 categories, which are App and framework respectively. Bundles of AppStore Apps are stored in  “/var/mobile/Containers/Bundle/Application/”, bundles of system Apps are stored in “/Applications/”, and bundles of frameworks are stored in “/System/Library/Frameworks” and “/System/Library/PrivateFrameworks”.

  - Grep: Grep is a built-in command on OSX; on iOS, it is ported by Saurik and
    installed accompanying with Cydia by default. grep can quickly narrow down the search scope when we want to find the source of a string. For example, if we want to find which binaries call [IMDAccount initWithAccountID:defaults:service:], we can rely on grep after we sshed into iOS:

    ```bash
    FunMaker-5:~ root# grep -r initWithAccountID:defaults:service: /System/Library/
    Binary file /System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7s matches
    grep: /System/Library/Caches/com.apple.dyld/enable-dylibs-to-override-cache: No such
    file or directory
    grep: /System/Library/Frameworks/CoreGraphics.framework/Resources/libCGCorePDF.dylib: No
    such file or directory
    grep: /System/Library/Frameworks/CoreGraphics.framework/Resources/libCMSBuiltin.dylib:
    No such file or directory
    grep: /System/Library/Frameworks/CoreGraphics.framework/Resources/libCMaps.dylib: No
    such file or directory
    grep: /System/Library/Frameworks/System.framework/System: No such file or directory
    ```

    From the result, we can see that the method appears in dyld_shared_cache_armv7s. Now, we can use grep again in the decached dyld_shared_cache_armv7s:

    ```bash
    snakeninnysiMac:~ snakeninny$ grep -r initWithAccountID:defaults:service:
    /Users/snakeninny/Code/iOSSystemBinaries/8.1_iPhone5
    Binary file
    /Users/snakeninny/Code/iOSSystemBinaries/8.1_iPhone5/dyld_shared_cache_armv7s matches
    grep:
    /Users/snakeninny/Code/iOSSystemBinaries/8.1_iPhone5/System/Library/Caches/com.apple.xpc
    /sdk.dylib: Too many levels of symbolic links
    grep:
    /Users/snakeninny/Code/iOSSystemBinaries/8.1_iPhone5/System/Library/Frameworks/OpenGLES.
    framework/libLLVMContainer.dylib: Too many levels of symbolic links
    Binary file
    /Users/snakeninny/Code/iOSSystemBinaries/8.1_iPhone5/System/Library/PrivateFrameworks/IM
    DaemonCore.framework/IMDaemonCore matches
    ```

    You can see that in the “/System/Library/” directory, [IMDAccount
    initWithAccountID:defaults:service:] appears in IMDaemonCore, so we can start our analysis from this binary.

  - Configuration files of daemons, which are plist formatted, are all stored in
    “/System/Library/LaunchDaemons/”, “/Library/LaunchDaemons” and
    “/Library/LaunchAgents/”. The “ProgramArguments” fields in these files are the absolute paths of daemon executables, such as:

```bash
snakeninnys-MacBook:~ snakeninny$ plutil -p
/Users/snakeninny/Desktop/com.apple.backboardd.plist
{
……
"ProgramArguments" => [
0 => "/usr/libexec/backboardd"
]
……
}
```



#### Locate Target Functions

- Use built in OSX search bar

- Grep: 

  ```bash
  snakeninnysiMac:~ snakeninny$ grep -r -i proximity
  /Users/snakeninny/Code/iOSPrivateHeaders/8.1
  /Users/snakeninny/Code/iOSPrivateHeaders/8.1/Frameworks/CoreLocation/CDStructures.h:
  char proximityUUID[512];
  /Users/snakeninny/Code/iOSPrivateHeaders/8.1/Frameworks/CoreLocation/CLBeacon.h:
  NSUUID *_proximityUUID;
  ……
  /Users/snakeninny/Code/iOSPrivateHeaders/8.1/SpringBoard/SpringBoard.h:-
  (_Bool)proximityEventsEnabled;
  /Users/snakeninny/Code/iOSPrivateHeaders/8.1/SpringBoard/SpringBoard.h:-
  (void)_proximityChanged:(id)arg1;
  ```

  

#### Testing Private Methods

Testing Objective-C methods is much simpler than testing C/C++ functions, which can be done via either CydiaSubstrate or Cycript.

- **<u>CydiaSubstrate</u>**: When testing methods, we mainly use CydiaSubstrate to hook them in order to determine when they’re called. Suppose we think  saveScreenShot: in SBScreenShooter.h is called during screenshot, we can write the following code to verify it:

  ```objective-c
  %hook SBScreenShotter
  - (void)saveScreenshot:(BOOL)screenshot
  {
  %orig;
  NSLog(@"iOSRE: saveScreenshot: is called");
  }
  %end
  ```

  Set the tweak filter to “com.apple.springboard”, package it into a deb using Theos and install it on iOS, then respring. If you feel a bit rusty, don’t worry, that’s normal; what we care about is stability rather than speed. After lock screen appears, press the home button and lock button at the same time to take a screenshot and then ssh into iOS to view the syslog:

  ```objective-c
  FunMaker-5:~ root# grep iOSRE: /var/log/syslog
  Nov 24 16:22:06 FunMaker-5 SpringBoard[2765]: iOSRE: saveScreenshot: is called
  ```

  

- <u>**Cycript**</u>: Since SBScreenShotter is a class in SpringBoard, we should inject Cycript into SpringBoard and call the method directly to test it out. Unlike tweaks, Cycript doesn’t ask for compilation and clearing up, which saves us great amount of time.

  ssh to iOS and then execute the following commands:

  ```bash
  FunMaker-5:~ root# cycript -p SpringBoard
  cy# [[SBScreenShotter sharedInstance] saveScreenshot:YES]
  ```

  Do you see a white flash on your screen with a shutter sound and a screenshot in your album, just like pressing home button and lock button together? OK, now it’s sure that calling this method manages to take a screenshot. To further satisfy our curiosity, press the up key on keyboard to repeat the last Cycript command and change YES to No.

  We still don’t know whether we should pass YES or NO to the argument, so we have to guess. By browsing the class-dump headers, we can see that most argument types are id, which is the generic type in Objective-C and is determined  in runtime. As a consequence, we can’t even make any guesses.



For the above screenshot example, whether the argument of saveScreenShot: is YES or NO just determines whether there is a white flash on screen. According to this clue, we can locate the suspicious SBScreenFlash class very soon, which contains a very interesting method flashColor:withCompletion:. We know that the flash can be
enabled or not, are there also any possibilities for us to change the flash color? Let’s write the following code to satisfy our curiosity.

```objective-c
%hook SBScreenFlash
- (void)flashColor:(id)arg1 withCompletion:(id)arg2
{
%orig;
NSLog(@"iOSRE: flashColor: %s, %@", object_getClassName(arg1), arg1); // [arg1
description] can be replaced by arg1
}
%end
```

After the tweak is installed, respring once and take a screenshot. Then ssh to iOS to check the syslog again, you should find information as follows:

```bash
FunMaker-5:~ root# grep iOSRE: /var/log/syslog
Nov 24 16:40:33 FunMaker-5 SpringBoard[2926]: iOSRE: flashColor:
UICachedDeviceWhiteColor, UIDeviceWhiteColorSpace 1 1
```

It can be seen that flash color is an object of type UICachedDeviceWhiteColor, and its
description is "UIDevice WhiteColorSpace 1 1". According to the Objective-C naming
conventions, UICachedDeviceWhiteColor is a class in UIKit, but we cannot find it in the
document, meaning it is a private class. Class-dump UIKit and then open
UICachedDeviceWhiteColor.h:

```objective-c
@interface UICachedDeviceWhiteColor : UIDeviceWhiteColor
{
}
- (void)_forceDealloc;
- (void)dealloc;
- (id)copy;
- (id)copyWithZone:(struct _NSZone *)arg1;
- (id)autorelease;
- (BOOL)retainWeakReference;
- (BOOL)allowsWeakReference;
- (unsigned int)retainCount;
- (id)retain;
- (oneway void)release;
@end
    
//It inherits from UIDeviceWhiteColor, so let’s continue with UIDeviceWhiteColor.h:
@interface UIDeviceWhiteColor : UIColor
{
float whiteComponent;
float alphaComponent;
struct CGColor *cachedColor;
long cachedColorOnceToken;
}
- (BOOL)getHue:(float *)arg1 saturation:(float *)arg2 brightness:(float *)arg3
alpha:(float *)arg4;
- (BOOL)getRed:(float *)arg1 green:(float *)arg2 blue:(float *)arg3 alpha:(float *)arg4;
- (BOOL)getWhite:(float *)arg1 alpha:(float *)arg2;
- (float)alphaComponent;
- (struct CGColor *)CGColor;
- (unsigned int)hash;
- (BOOL)isEqual:(id)arg1;
- (id)description;
- (id)colorSpaceName;
- (void)setStroke;
- (void)setFill;
- (void)set;
- (id)colorWithAlphaComponent:(float)arg1;
- (struct CGColor *)_createCGColorWithAlpha:(float)arg1;
- (id)copyWithZone:(struct _NSZone *)arg1;
- (void)dealloc;
- (id)initWithCGColor:(struct CGColor *)arg1;
- (id)initWithWhite:(float)arg1 alpha:(float)arg2;
@end
```

UIDeviceWhiteColor inherits from UIColor. Since UIColor is a public class, stop our
analysis at this level is enough for us to get the result. For other id type arguments, we can apply the same solution.

Next, let’s use Cycript to test this method and see what effect it is when we pass [UIColor magentaColor] as the argument.

```bash
FunMaker-5:~ root# cycript -p SpringBoard
cy# [[SBScreenFlash mainScreenFlasher] flashColor:[UIColor magentaColor]
withCompletion:nil]
```

A magenta flash scatters on the screen and it is much cooler than the original white flash. Check the album and we don’t find a new screenshot. Therefore we guess that this method is just for flashing the screen without actually performing the screenshot operation. Aha, a new tweak inspiration arises, we can hook flashColor:withCompletion: and pass it a custom color to enrich the screen flash with more colors.