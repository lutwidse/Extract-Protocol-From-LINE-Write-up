© 2020 Lutwidse

## 0. Introduction to analyze LINE
Hi, I'm Lutwidse who is learning about reverse engineering.  
I think each country has it's own popular messaging application.  
In my country Japan, most users used LINE.  
I was very interested in LINE's communication protocol but however, LINE is not an OSS application.  
So I decided to reverse engineer it.  

## 1. But what exactly LINE is

*Referenced from "Line (software)
from Wikipedia, the free encyclopedia"*

> Line (styled in all caps as LINE) is a freeware app for instant communications on electronic devices such as smartphones, tablet computers, and personal computers.   Line users exchange texts, images, video and audio, and conduct free VoIP conversations and video conferences.

   - > As its competitor Kakao dominated the South Korean messaging market, Naver Corporation launched a messenger application NAVER Talk in February 2011 in South Korea. However, because the South Korean messaging market was dominated by Kakao, the business of NAVER Talk was suppressed. Naver Corporation was expanding their messaging application and targeted to other countries' messaging markets which have not been developed yet. Naver Corporation released their messaging application, which changed its name to 'LINE', to the Japanese messaging market in 2011. As LINE became a huge success, finally NAVER combined NAVER Talk and LINE in March 2012.

Really interesting that LINE got huge success in Japan.  
Currently, there are no domestic messaging applications in Japan, and people tend to avoid switching to new services, so even if they are created, they are unlikely to become widespread.  
In the category I know, crowdfunding of domestic secure applications using blockchain technology is carried out. However, there are only 56 donors (2020-11-16-0350), and when calculating the proportion of the population between the ages of 15 and 64 who regularly use smartphones, only about 0.0000007% of the population has donated.  
As a fact. The "mottainai" spirit of using conventional products is at the root.

## 2. Communication protocol overview

*Referenced from LINE Encryption Overview
Technical Whitepaper*

3.1 Protocol Overview
   - > The main transport protocol used in LINE mobile clients is based on SPDY 2.0 [1]. While the
SPDY protocol typically relies on TLS to establish an encrypted channel, LINE’s
implementation uses a lightweight handshake protocol to establish the transport keys used
for application data encryption.
Our handshake protocol is loosely based on the 0-RTT handshake in TLS v1.3 [2]. LINE’s
transport encryption protocol uses elliptic curve cryptography (ECC) with the secp256k1
curve [3] to implement key exchange and server identity verification. We use AES for
symmetric encryption and derive symmetric keys using HKDF [4].
We describe the protocol in more detail below.

Okay, so basically LINE Android/iOS is using SPDY 2.0 for communication.  
SPDY protocol is developed by Google to purpose supporting the HTTP.  
But it's abandoned in 2016 due to prioritizing developing HTTP/2.  

Let's see if we can get something from the packet.  
I used HttpCanary for capturing packets.  
Also, I used both LINE / LINE Lite and armv7/armv8 for efficient debugging.

**QrCode - Login Session**

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/1.png?raw=true" width="400" height="400">

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/2.png?raw=true" width="400" height="400">

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/3.png?raw=true" width="400" height="400">

In those packets, we can see that LINE is using Apache Thrift compact protocol for communication to connect "/acct/lgn/sq/v1".  
It's API and probably "/account/login/".  
As we can see LINE is generating a session in the thrift API endpoint with by createSession function.

Now we need to understand what Thrift is and behavior.

## 3. Let's deep into Apache Thrift

Apache Thrift is the protocol made by Facebook for scalable cross-language services development.  
Such as Thrift is called Interface Description Language a.k.a IDL.  
The developer defines data types in the .thrift file and compiles the definition file with Thrift compiler to use in any programming language.

*A simple example of Thrift IDL definition.*

```thrift
exception HelloError
{
  1:i32 errcode,
  2:string message
}

struct HelloResponse
{
  1:string message;
}

struct HelloRequest{}

service HelloService
{
  HelloResponse HelloWorld(
    1:HelloRequest request)
    throws (1:HelloError err);
}
```

Thrift IDL has six types.
- Base Types
- Special Types
- Structs
- Containers
- Exceptions
- Services

And the formula is FieldID: Types name.  
FieldId is used to make sure that both communications data are correct.

## 4. It's time to deserialize LINE's communication data

Well, now we know LINE is using Thrift for communication.  
However, the packets are serialized.  
So let's hook TServiceClient in LINE lite by using a decompiler/debugger.  
TServiceClient is the core of communication protocol.

*Referenced from Java Apache Thrift javadoc*

```Java
public abstract class TServiceClient
extends java.lang.Object
A TServiceClient is used to communicate with a TService implementation across protocols and transports.
```

```Java
protected void sendBase(java.lang.String methodName,
                        TBase args)
                 throws TException
Throws:
TException
```

```Java
protected void receiveBase(TBase result,
                           java.lang.String methodName)
                    throws TException
Throws:
TException
```

Okay, we might able to hook packets with these functions!

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/4.png?raw=true">

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/5.png?raw=true">

Yes, we reached TServiceClient in the decompiler.  
It's probably obfuscated by llvm-obfuscator which is called "ORK" that made by LINE Corporation.  
But it's easily to understand.  
function a is receiveBase, function b is sendBase.  
So I coded an Xposed application for hooking that.

```Java
public class ThriftHooker implements IXposedHookLoadPackage {
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lparam) throws Throwable {
        if (lparam.packageName.equals("com.linecorp.linelite")) {
            Class TServiceClient = lparam.classLoader.loadClass("w.a.a.TServiceClient");

            XposedHelpers.findAndHookMethod(TServiceClient, "b", String.class, "w.a.a.TProtocol", new XC_MethodHook() {
                @RequiresApi(api = Build.VERSION_CODES.O)

                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    XposedBridge.log("[TServiceClient sendBase]: " + " [ " + param.args[1] + " ] " + param.args[1].toString());
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                }
            });

            XposedHelpers.findAndHookMethod(TServiceClient, "a", "w.a.a.TProtocol", String.class, new XC_MethodHook() {
                @RequiresApi(api = Build.VERSION_CODES.O)

                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    ArrayList<String> args = new ArrayList<String>();
                    for (Object arg: param.args) {
                        args.add(arg.toString());
                    }
                    XposedBridge.log("[TServiceClient receiveBase]: " + " [ " + param.args[1] + " ] " + param.args[0].toString());
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                }
            });
        }
    }
}
```

And as the result...

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/6.png?raw=true">

**Boom!**  
A bunch of packets is readable now.

```
[TServiceClient sendBase]:  [ getServerTime_args() ] getServerTime_args()
[TServiceClient sendBase]:  [ createSession_args(request:CreateQrSessionRequest()) ] createSession_args(request:CreateQrSessionRequest())
[TServiceClient receiveBase]:  [ getServerTime ] getServerTime_result(success:0, e:null)
[TServiceClient receiveBase]:  [ createSession ] createSession_result(success:null, e:null)
[TServiceClient sendBase]:  [ createQrCode_args(request:CreateQrCodeRequest(authSessionId:**********************************************************39587a69)) ] createQrCode_args(request:CreateQrCodeRequest(authSessionId:**********************************************************39587a69))
[TServiceClient receiveBase]:  [ createQrCode ] createQrCode_result(success:null, e:null)
[TServiceClient sendBase]:  [ verifyCertificate_args(request:VerifyCertificateRequest(authSessionId:**********************************************************39587a69, certificate:********************************************************ec433014)) ] verifyCertificate_args(request:VerifyCertificateRequest(authSessionId:**********************************************************39587a69, certificate:********************************************************ec433014))
[TServiceClient receiveBase]:  [ verifyCertificate ] verifyCertificate_result(success:null, e:null)
[TServiceClient sendBase]:  [ qrCodeLogin_args(request:QrCodeLoginRequest(authSessionId:**********************************************************39587a69, systemName:G011A, autoLoginIsRequired:true)) ] qrCodeLogin_args(request:QrCodeLoginRequest(authSessionId:**********************************************************39587a69, systemName:G011A, autoLoginIsRequired:true))
[TServiceClient receiveBase]:  [ qrCodeLogin ] qrCodeLogin_result(success:null, e:null)
```

## 5. More deep into QrCode login method

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/7.png?raw=true" width="600" height="400">

In this bytecode, LINE is generating a URL for QrCode login.  
When we open the URL in the LINE application, PinCode confirmation will be displayed.  
As code shows the key pairs called ecdh are calculated with Curve25519.

*Referenced from cr.yp.to*

> Given a user's 32-byte secret key, Curve25519 computes the user's 32-byte public key. Given the user's 32-byte secret key and another user's 32-byte public key, Curve25519 computes a 32-byte secret shared by the two users. This secret can then be used to authenticate and encrypt messages between the two users.

So the final URL is something like that
```
https://line.me/R/au/g/authSessionId?secret=ecdh&e2eeVersion=version
```

After some research, I noticed that the unhookable functions is existing.

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/8.png?raw=true" width="600" height="400">

The function seems to await for the QrCode login.  
Others existed as well, but I will omit them here.  

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/9.png?raw=true" width="600" height="600">

Here is the dump of endpoints that used in QrCode login and messaging.
Of particular importance is
- SECONDARY_LOGIN /ACCT/lgn/sq/v1
  - QrCode Login
- SECONDARY_LOGIN_PERMIT /ACCT/lp/lgn/sq/v1
  - QrCode Login Validate
- TalkService /S4
  - Messaging API
- PollingService /P4
  - Receive Operations Cycle

## 6. Rebuild Thrift IDL from bytecode

Alright, now we understand tons of behavior of LINE.  
What to do next is rebuild the Thrift IDL.  
As one method, I chose Smali.  
If you are Java application developer, you might know, when you build the apk, it contains a .dex file which contains Dalvik bytecode.  

I won't go into too much detail, but Java is an intermediate language and easy to decompile.   However, reading bytecode is not easy.  
So we will use baksmali to disassembly/assembly, apktool is the best choice I think.  
After disassembled that with apktool, search codes with Linux command.

```shell
$find . -name "*.smali" | xargs grep -E "_result|_args"
```

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/10.png?raw=true">

Nice!  
Smali's syntax is similar to x86-32 assembly and I was familiar with assembly so I could understand it in about 20 minutes.  
And after understanding, I wrote a program in Golang and Python that automatically rebuilds Thrift IDL from Smali.  
The algorithm is very simple.  
I think the lexical analysis is also useful, but I made the processing for the pattern only with the if statement.  
It's so easy that I don't think it's necessary to write it but anyway I will explain the algorithm in bullet points.  
**For convenience, we refer to args as program_args.**

- _result
  - Struct
  - Exception

- _args
  - Struct

 > Rules
  - service name and its own functions are can be known from Impl
    - jp\naver\line\android\thrift\client\impl
  - Response can be known from _result
    - When _result has no Struct, it's a void function.
  - Request can be known from _args
  - FieldID, Types, the name is can be known from invoke-direct.
  - instance fields are linked to program_args of direct methods
    - The Type is definitely Types or Struct or Enum
    - If instance fields are not enough to link program_args it is optional and can be known from invoke-direct.
  - A struct that contains "Exception" in the name is definitely an Exception function.
  - Enums are rebuildable from reading invoke-direct
  - typedef is can be known from # direct methods

*Eaxmple of rebuild createQrCode*

```smali
# instance fields
.field public d:Lb/a/d/a/a/b/a/j;

// b/a/d/a/a/b/a/j = Response

.field public e:Lb/a/d/a/a/b/a/r;

// b/a/d/a/a/b/a/r = Exception


# direct methods
.method public static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lw/a/a/j/l;

    const-string v1, "createQrCode_result"

    invoke-direct {v0, v1}, Lw/a/a/j/l;-><init>(Ljava/lang/String;)V

    sput-object v0, Lb/a/d/a/a/b/a/m0;->f:Lw/a/a/j/l;

    .line 2
    new-instance v0, Lw/a/a/j/c;

    const-string v1, "success"

    const/16 v2, 0xc

    const/4 v3, 0x0

    invoke-direct {v0, v1, v2, v3}, Lw/a/a/j/c;-><init>(Ljava/lang/String;BS)V

    /*
    v1 = name
    v2 = Type
    v3 = FieldID
    */

    sput-object v0, Lb/a/d/a/a/b/a/m0;->g:Lw/a/a/j/c;

...
```

```smali
# instance fields
.field public d:Lb/a/d/a/a/b/a/i;

// b/a/d/a/a/b/a/i = request

# direct methods
.method public static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lw/a/a/j/l;

    const-string v1, "createQrCode_args"

    invoke-direct {v0, v1}, Lw/a/a/j/l;-><init>(Ljava/lang/String;)V

    sput-object v0, Lb/a/d/a/a/b/a/l0;->e:Lw/a/a/j/l;

    .line 2
    new-instance v0, Lw/a/a/j/c;

    const-string v1, "request"

    const/16 v2, 0xc

    const/4 v3, 0x1

    invoke-direct {v0, v1, v2, v3}, Lw/a/a/j/c;-><init>(Ljava/lang/String;BS)V

    /*
    v1 = name
    v2 = Type
    v3 = FieldID
    */

    sput-object v0, Lb/a/d/a/a/b/a/l0;->f:Lw/a/a/j/c;

...
```

```thrift

enum g_a_c_u0_a_c_b_c
{
  INTERNAL_ERROR = 0;
  ILLEGAL_ARGUMENT = 1;
  VERIFICATION_FAILED = 2;
  NOT_ALLOWED_QR_CODE_LOGIN = 3;
  VERIFICATION_NOTICE_FAILED = 4;
  RETRY_LATER = 5;
  INVALID_CONTEXT = 100;
  APP_UPGRADE_REQUIRED = 101;
}

exception SecondaryQrCodeException
{
  1:g_a_c_u0_a_c_b_c code;
  2:string alertMessage;
}

struct CreateQrCodeResponse
{
  1:string callbackUrl;
}

struct CreateQrCodeRequest
{
  1:string authSessionId;
}

service SecondaryQrcodeLoginService
{
  CreateQrCodeResponse createQrCode(
  1:CreateQrCodeRequest request) throws (1:SecondaryQrCodeException e);
}
```

## 7. Login LINE with CLI and use functions

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/11.png?raw=true">

Seems successfully generated a Python library from the rebuilt Thrift IDL.  
All you have to do now is implement the API in Python!  
*The longer you wait for something, the more you appreciate it when you get it. Because anything worth having is definitely worth waiting for. - Susan Gale*

```python
from LutwidseAPI.TalkService import TalkService

# Login algorithm is omitted due to code as hell as spaghetti.
msg = Message
msg = Message(to=groupId, text="Hello World")
# groupId can be known with packet analysis or you can use Thrift functions that get group information.
client.sendMessage(reqSeq, msg)
```

**FIRE IN THE HOLE!**

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/12.png?raw=true">

<img src="https://github.com/Lutwidse/Extract-Protocol-From-LINE-Write-up/blob/images/13.png?raw=true" width="700" height="500">

## 8. Fetching operations

If you hooking LINE long time, you would notice that function called fetchOps is rotating every few minutes.

*Referenced from wikipedia, the free encyclopedia*

> long polling (uncountable)
>> (computing) A technology where the client requests information from the server without expecting an immediate response.

So the function is used to wait and catch the user's actions, such as "Your friend sent a message to you/group" "somebody changed the group's icon".

```
[TServiceClient sendBase]:  [ fetchOps_args(localRev:393831, count:50, globalRev:295818, individualRev:1286) ] fetchOps_args(localRev:393831, count:50, globalRev:295818, individualRev:1286)
```

But how do globalRev and individualRev is deciding?
So let's debug the operations with the API your own made.  
Now, you should be wondering about the strange sequence returned.

```
createdTime 0
param1 128658291
param2 295818notice23moretab304stickershop234channel205denykeyword244connectioninfo148buddy256timelineinfo8themeshop41callrate43configuration348sticon52suggestdictionary144suggestsettings281usersettings0analyticsinfo289searchpopularkeyword224searchnotice169timeline99searchpopularcategory287extendedprofile254seasonalmarketing34newstab84suggestdictionaryv2106chatappsync337agreements323instantnews147emojimapping96searchbarkeywords38shopping256chateffectbg223chateffectkw27searchindex276hubtab109payruleupdated144smartch244homeservicelist296timelinestory289wallettab261podtab183
reqSeq -1
revision -1
type 0
```

Assuming you like puzzles, it's very easy to answer.

- fetchOps
  - localRev = your account's fetched operations count
  - count = how many operations you will fetch
  - individualRev = first numbers of param1
  - globalRev = first numbers of param2

I have no idea know why LINE deciding the key with that.  
Anyway, you can confirm it works properly.

**Thank you for reading - Lutwidse**

### References
> https://en.wikipedia.org/wiki/Line_(software)

> https://www.stat.go.jp/data/jinsui/2019np/index.html

> https://camp-fire.jp/projects/view/315308

> https://scdn.line-apps.com/stf/linecorp/en/csr/line-encryption-whitepaper-ver1.0.pdf

> https://thrift.apache.org/docs/idl

> https://people.apache.org/~thejas/thrift-0.9/javadoc/org/apache/thrift/TServiceClient.html

> https://engineering.linecorp.com/ja/blog/ork-vol-1/

> https://cr.yp.to/ecdh.html

> https://github.com/JesusFreke/smali

> https://en.wiktionary.org/wiki/long_polling

> https://en.wikipedia.org/wiki/Push_technology
