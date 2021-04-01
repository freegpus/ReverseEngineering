# Tweak Example

**<u>Inject Cycript into Mail</u>**

Firstly use the skill mentioned in section “dumpdecrypted” to locate the process name of Mail, and inject with Cycript:

```bash
FunMaker-5:~ root# ps -e | grep /Applications
363 ?? 0:06.94 /Applications/MobileMail.app/MobileMail
596 ?? 0:01.50
/Applications/MessagesNotificationViewService.app/MessagesNotificationViewService
623 ?? 0:08.50 /Applications/InCallService.app/InCallService
713 ttys000 0:00.01 grep /Applications
FunMaker-5:~ root# cycript -p MobileMail
```

**<u>Examine the view hierarchy of “Mailboxes” view, and locate “compose” button</u>**

The private method [UIView recursiveDescription] returns the view hierarchy of UIView.
Normally, the current view is consists of at least one UIWindow object, and UIWindow inherits from UIView, so we can use this private method to examine the view hierarchy of current view. Its usage follows this pattern:

```bash
cy# ?expand
expand == true
```

First of all, execute “?expand” in Cycript to turn on “expand”, so that Cycript will translate control characters such as “\n” to corresponding formats and give the output a better readability.

```bash
cy# [[UIApp keyWindow] recursiveDescription]
```

UIApp is the abbreviation of [UIApplication sharedApplication], they’re equivalent. Calling the above method will print out view hierarchy of keyWindow, and output like this:

```bash
@"<UIWindow: 0x14587a70; frame = (0 0; 320 568); gestureRecognizers = <NSArray:
0x147166b0>; layer = <UIWindowLayer: 0x14587e30>>
| <UIView: 0x146e6180; frame = (0 0; 320 568); autoresize = W+H; gestureRecognizers =
<NSArray: 0x146e98d0>; layer = <CALayer: 0x146e61f0>>
| | <UIView: 0x146e5f60; frame = (0 0; 320 568); layer = <CALayer: 0x1460ec40>>
| | | <_MFActorItemView: 0x14506a30; frame = (0 0; 320 568); layer = <CALayer:
0x14506c10>>
| | | | <UIView: 0x145074b0; frame = (-0.5 -0.5; 321 569); alpha = 0; layer
= <CALayer: 0x14507520>>
| | | | <_MFActorSnapshotView: 0x14506f70; baseClass = UISnapshotView; frame
= (0 0; 320 568); clipsToBounds = YES; hidden = YES; layer = <CALayer: 0x145071c0>>
……
| | <MFTiltedTabView: 0x146e1af0; frame = (0 0; 320 568); userInteractionEnabled =
NO; gestureRecognizers = <NSArray: 0x146f2dd0>; layer = <CALayer: 0x146e1d50>>
| | | <UIScrollView: 0x146bfa90; frame = (0 0; 320 568); gestureRecognizers =
<NSArray: 0x146e1e90>; layer = <CALayer: 0x146c8740>; contentOffset: {0, 0};
contentSize: {320, 77.5}>
| | | <_TabGradientView: 0x146e7010; frame = (-320 -508; 960 568); alpha = 0;
userInteractionEnabled = NO; layer = <CAGradientLayer: 0x146e7d80>>
| | | <UIView: 0x146e29c0; frame = (-10000 568; 10320 10000); layer = <CALayer:
0x146e2a30>>"
```

Description of every subview and sub-subview of keyWindow will be completely presented in <……>, including their memory addresses, frames and so on. The indentation spaces reflect the relationship between views. Views on the same level will have same indentation spaces, such as UIScrollView, _TabGradientView and UIView at the bottom; and less indented views are the superviews of more indented views, for example, UIScrollView, _TabGradientView, and UIView are subviews of MFTiltedTabView. By using “#” in Cycript, we can get any view object in keyWindow like this:

```bash
cy# tabView = #0x146e1af0
#"<MFTiltedTabView: 0x146e1af0; frame = (0 0; 320 568); userInteractionEnabled = NO;
gestureRecognizers = <NSArray: 0x146f2dd0>; layer = <CALayer: 0x146e1d50>>"
```

Of course, through other methods of UIApplication and UIView, it is also feasible to get
views we are interested in, for example:

```bash
cy# [UIApp windows]
@[#"<UIWindow: 0x14587a70; frame = (0 0; 320 568); gestureRecognizers = <NSArray:
0x147166b0>; layer = <UIWindowLayer: 0x14587e30>>",#"<UITextEffectsWindow: 0x15850570;
frame = (0 0; 320 568); opaque = NO; gestureRecognizers = <NSArray: 0x147503e0>; layer =
<UIWindowLayer: 0x1474ff10>>"]
```

The above code can get all windows of this App:

```bash
cy# [#0x146e1af0 subviews]
@[#"<UIScrollView: 0x146bfa90; frame = (0 0; 320 568); gestureRecognizers = <NSArray:
0x146e1e90>; layer = <CALayer: 0x146c8740>; contentOffset: {0, 0}; contentSize: {320,
77.5}>",#"<_TabGradientView: 0x146e7010; frame = (-320 -508; 960 568); alpha = 0;
userInteractionEnabled = NO; layer = <CAGradientLayer: 0x146e7d80>>",#"<UIView:
0x146e29c0; frame = (-10000 568; 10320 10000); layer = <CALayer: 0x146e2a30>>"]
cy# [#0x146e29c0 superview]
#"<MFTiltedTabView: 0x146e1af0; frame = (0 0; 320 568); userInteractionEnabled = NO;
gestureRecognizers = <NSArray: 0x146f2dd0>; layer = <CALayer: 0x146e1d50>>"
```

The above code can get subviews and superviews. In a word, we can get any view objects that are visible on UI by combining the above methods, which lays the foundation for our next steps.

### Locate Compose Button

In order to locate “compose” button, we need to find out the corresponding control object. To accomplish this, the regular approach is to examine control objects one by one. For views like <UIView: viewAddress; …>, we call [#viewAddress setHidden:YES] for everyone of them, and the disappeared control object is the matching one. Of course, some tricks could accelerate the examination; because on the left side of this button there’re two lines of sentences, we can infer that the button shares the same superview with this two sentences; if we can find out the superview, the rest of work is only examining subviews of this superview, hence reduce our work burden. Commonly, texts will be printed in description, so we can directly search “3 Unsent Messages” in recursiveDescription:

```bash
| | | | | | | | <MailStatusUpdateView: 0x146e6060; frame = (0 0;
182 44); opaque = NO; autoresize = W+H; layer = <CALayer: 0x146c8840>>
| | | | | | | | | <UILabel: 0x14609610; frame = (40 21.5; 102
13.5); text = ‘3 Unsent Messages’; opaque = NO; userInteractionEnabled = NO; layer =
<_UILabelLayer: 0x146097f0>>
```

Thereby, we get its superview, i.e. MailStatusUpdateView. If the button is a subview of
MailStatusUpdateView, then when we call [MailStatusUpdateView setHidden:YES], the button would disappear. Let’s try it out:

```bash
cy# [#0x146e6060 setHidden:YES]
```

However, only the sentences are hidden, the button remains visible

This indicates that the level of MailStatusUpdateView is lower than or equal to the button, right? So, next let’s check the superview of MailStatusUpdateView. From recursiveDescription, we realize that its superview is MailStatusBarView:

```bash
| | | | | | | <MailStatusBarView: 0x146c4110; frame = (69 0; 182
44); opaque = NO; autoresize = BM; layer = <CALayer: 0x146f9f90>>
| | | | | | | | <MailStatusUpdateView: 0x146e6060; frame = (0 0;
182 44); opaque = NO; autoresize = W+H; layer = <CALayer: 0x146c8840>>
```

Try to hide it and see if the button disappears:

```bash
cy# [#0x146e6060 setHidden:NO]
cy# [#0x146c4110 setHidden:YES]
```

It’s disappointing; two sentences are hidden but not the button, which means that the level of MailStatusBarView is still not high enough, let’s keep looking for its superview, i.e. UIToolBar. Let’s repeat the operation to hide UIToolBar:

```bash
cy# [#0x146c4110 setHidden:NO]
cy# [#0x146f62a0 setHidden:YES]
```



### Find the UI Function of "compose" button

UI function of a button is its response method after tapping it. Usually we use [UIControl addTarget:action:forControlEvents:] to add a response method to a UIView object (I haven’t seen any exceptions so far). Meanwhile, the method [UIControl
actionsForTarget:forControlEvent:] offers a way to get the response method of a UIControl object. Based on this, as long as the view we get in the last step is a subclass of UIControl (Again, I haven’t seen any exceptions so far), we can find out its response method. More specifically in this example, we do it like this:

```bash
cy# button = #0x14798410
#"<UIToolbarButton: 0x14798410; frame = (285 0; 23 44); hidden = YES; opaque = NO;
gestureRecognizers = <NSArray: 0x14799510>; layer = <CALayer: 0x14798510>>"
cy# [button allTargets]
[NSSet setWithArray:@[#"<ComposeButtonItem: 0x14609d00>"]]]
cy# [button allControlEvents]
64
cy# [button actionsForTarget:#0x14609d00 forControlEvent:64]
@["_sendAction:withEvent:"]
```

Therefore, after tapping “compose” button, Mail calls [ComposeButtonItem
_sendAction:withEvent:], we have successfully found the response method. Inject with Cycript, locate UI control object, and then find out its UI function, it’s fairly easy as you see. 