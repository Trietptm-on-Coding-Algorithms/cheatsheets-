### ApateDNS
```
ApateDNS is a tool for controlling DNS responses. Its interface is an
easy-to-use GUI. As a phony DNS server, ApateDNS spoofs DNS responses
to a user-specified IP address by listening on UDP port 53 on the local
machine. ApateDNS also automatically configures the local DNS server
to localhost. When you exit ApateDNS, it restores the original local DNS
settings. Use ApateDNS during dynamic analysis, as described in Chapter 3.
You can download ApateDNS for free from http://www.mandiant.com/.
```
### Autoruns
```
Autoruns is a utility with a long list of autostarting locations for Windows.
For persistence, malware often installs itself in a variety of locations,
including the registry, startup folder, and so on. Autoruns searches
466 Appendix B
various possible locations and reports to you in a GUI. Use Autoruns
for dynamic analysis to see where malware installed itself. You can
download Autoruns as part of the Sysinternals Suite of tools from http://
www.sysinternals.com/.
```
### BinDiff
```
BinDiff is a powerful binary comparison plug-in for IDA Pro that allows
you to quickly compare malware variants. BinDiff lets you pinpoint new
functions in a given malware variant and tells you if any functions are
similar or missing. If the functions are similar, BinDiff indicates how similar
they are and compares the two, as shown in Figure B-1.
Figure B-1: BinDiff difference comparison showing code missing from the variant’s function
As you can see in Figure B-1, the left side of the graph is missing two
boxes that appear in the right side. You can zoom in and examine the
missing instructions. BinDiff will also guess at how similar the overall
binary is to one that you are comparing, though you must generate an
IDB file for both the original and the variant malware for this to work.
(If you have a fully labeled IDB file for the comparison, you will be able
to more easily recognize what is actually similar in the binary.)
BinDiff is available for purchase from http://www.zynamics.com/.
```
### BinNavi
```
BinNavi is a reverse-engineering environment similar to IDA Pro. Its
strength lies in its graphical approach to reverse-engineering code. And,
unlike IDA Pro, BinNavi can centrally manage your previously analyzed
databases, which helps to track information; team members can easily
work on the same project and share information and findings. BinNavi
is available for purchase from http://www.zynamics.com/.
``` 
### Bochs
```
Bochs is an open source debugger that simulates a complete x86 computer.
Bochs is most useful when you want to debug a short code snippet
in IDA Pro. IDA Pro supports a direct debugging mode of the IDB file
using Bochs. When debugging in this mode, the input file format isn’t
important—it can be a DLL, shellcode dump, or any other database that
contains x86 code. You can simply point to the code snippet and start
debugging. This approach is often useful when dealing with encoded
strings or configuration data. You can download Bochs for free from
http://bochs.sourceforge.net/. A tutorial on installing and using Bochs in
IDA Pro can be found at http://www.hex-rays.com/products/ida/debugger/
bochs_tut.pdf.
```
### Burp Suite
```
The Burp Suite is typically used for testing web applications. It can be
configured to allow malware analysts to trap specific server requests and
responses in order to manipulate what is being delivered to a system.
When Burp is set up as a man-in-the-middle, you can modify HTTP or
HTTPS requests by changing the headers, data, and parameters sent by
the malware to a remote server in order to force the server to give you
additional information. You can download the Burp Suite from http://
portswigger.net/burp/.
```
### Capture BAT
```
Capture BAT is a dynamic analysis tool used to monitor malware as it
is running. Capture BAT will monitor the filesystem, registry, and process
activity. You can use exclusion lists (including many preset ones)
to remove the noise in order to focus on the malware you are analyzing.
While Capture BAT doesn’t have an extensive GUI like Process Monitor,
it’s open source, so you can modify it. You can download Capture BAT
for free from http://www.honeynet.org/.
```
### CFF Explorer
```
CFF Explorer is a tool designed to make PE editing easy. The tool is useful
for editing resource sections, adding imports, or scanning for signatures.
CFF Explorer supports x86 and x64 systems, and it can handle
.NET files without having the .NET Framework installed. You can download
CFF Explorer for free from http://www.ntcore.com/.
```
### Deep Freeze
```
Deep Freeze from Faronics is a useful tool to use when performing malware
analysis on physical hardware. It provides a VMware snapshotting
capability for real hardware. You can run your malware, analyze it, and
then just reboot. All the damage done by the malware will be undone,
and your system will be back to a clean state. Deep Freeze is available for
purchase from http://www.faronics.com/.
```
### Dependency Walker
```
Dependency Walker is a static analysis tool used to explore DLLs and
functions imported by a piece of malware. It works on both x86 and x64
binaries, and builds a hierarchical tree diagram of all DLLs that will be
loaded into memory when the malware is run. We discuss Dependency
Walker in Chapter 1. You can download it for free from http://www
.dependencywalker.com/.
```
### Hex Editors
```
Hex editors allow you to edit and view files containing binary data. Many
hex editors are available, such as WinHex (our choice in this book), Hex
Workshop, 010 Editor, HexEdit, Hex Editor Neo, FileInsight, and Flex-
HEX. When choosing a hex editor, look for features like a solid GUI,
binary comparison, many data-decoding options (such as multibyte XOR),
a built-in hash calculator, file format parsing, pattern searching, and so
on. Many of these tools are available for purchase, but most come with a
trial version.
```
### Hex-Rays Decompiler
```
The Hex-Rays Decompiler is a powerful, but expensive, plug-in for IDA
Pro that attempts to convert assembly code into human-readable, C-like
pseudocode text. This tool installs an F5 “cheat button.” When you are
looking at disassembly in IDA Pro, press F5 to have the plug-in open a
new window with the C code. Figure B-2 shows what the pseudocode
looks like for a code snippet from a piece of malware.
Figure B-2: Hex-Rays Decompiler showing C-like pseudocode generated from assembly
In the example in Figure B-2, the Hex-Rays Decompiler turned more
than 100 assembly instructions into just eight lines of C code. Notice that
the plug-in will use your renamed variable names from IDA Pro. In this
example, you can easily see the parameters that are passed to a function,
and nested if statements are more obvious.
We find this plug-in particularly useful when trying to decipher difficult
encoding routines. In some cases, you can even copy and paste
the decompiler’s output and use it to write a decoding tool. Hex-Rays
Decompiler is the best tool on the market for decompiling, but it’s not
without its flaws. The Hex-Rays Decompiler is available for purchase
from http://www.hex-rays.com/.
```
### IDA Pro
```
IDA Pro is the most widely used disassembler for malware analysis. We
discuss IDA Pro extensively throughout the book, and Chapter 5 provides
an in-depth introduction to the tool. We recommend the commercial
version from http://www.hex-rays.com/. A freeware version is available
from http://www.hex-rays.com/products/ida/support/download_freeware.shtml.
```
### Immunity Debugger
```
Immunity Debugger (ImmDbg) is a freely available user-mode debugger.
It is derived from the OllyDbg 1.1 source code, as we discuss in
Chapter 9, except that ImmDbg has cosmetically modified the OllyDbg
GUI and added a fully functional Python interpreter with an API. In
“Scriptable Debugging” on page 200 and the Chapter 13 labs, we demonstrate
how to use ImmDbg’s Python scripting ability. You can download
ImmDbg from http://www.immunityinc.com/.
```
### Import REConstructor
```
Import REConstructor (ImpREC) is a useful tool when you are manually
unpacking a piece of malware. The import address table (IAT) is often
damaged when you dump memory while unpacking, and you can use
ImpREC to repair the table. You provide the malware running in memory
and a dumped version on disk, and ImpREC does its best to repair
the binary. You can download ImpREC for free from http://tuts4you.com/
download.php?view.415.
```
### INetSim
```
INetSim is a Linux-based software suite for simulating common network
services that we find useful for dynamic analysis. Be sure to install it on a
Linux virtual machine, and set it up on the same virtual network as your
malware analysis Windows VM. INetSim can emulate many popular services,
such as a Microsoft Internet Information Services (IIS) web server,
and can even listen on all ports for incoming connections. We discuss
INetSim in Chapter 3. You can download it for free from http://www
.inetsim.org/.
```
### LordPE
```
LordPE is a free tool for dumping an executable from memory. It allows
PE editing and can be used to repair a program you dumped from memory
using another method. LordPE is most commonly used for unpacking
malware. You can download it for free from http://www.woodmann
.com/collaborative/tools/index.php/LordPE.
```
### Malcode Analyst Pack
```
The Malcode Analyst Pack contains a series of utilities, one of which
installs useful Windows shell extensions for strings, an MD5 hash calculator,
and a CHM decompile option. The CHM decompile option is
handy when dealing with malicious Windows help files. Also included is
FakeDNS, a useful tool for spoofing DNS responses to a user-specified
address. While these utilities are no longer officially supported, you
might still be able to download them from http://labs.idefense.com/
software/download/?downloadID=8.
```
### Memoryze
```
Memoryze is a free memory forensic tool that enables you to dump and
analyze live memory. You can use Memoryze to acquire all of live memory
or just individual processes, as well as to identify all modules loaded
on a given system, including drivers and kernel-level executables. Memoryze
also can detect rootkits and the hooks they install. If you choose to
use Memoryze, be sure to download Audit Viewer, a tool for visualizing
Memoryze’s output that makes the memory analysis process quicker and
more intuitive. Audit Viewer includes a malware rating index to help you
identify suspicious content in your memory dumps. You can download
Memoryze and Audit Viewer for free from http://www.mandiant.com/.
```
### Netcat
```
Netcat, known as the “TCP/IP Swiss Army knife,” can be used to monitor
or start inbound and outbound connections. Netcat is most useful during
dynamic analysis for listening on ports that you know the malware
connects to, because Netcat prints all the data it receives to the screen
via standard output. We cover Netcat usage for dynamic analysis in Chapter
3 and also talk about how attackers use it in Chapter 11. Netcat is
installed by default in Cygwin and on most Linux distributions. You can
download the Windows version for free from http://joncraton.org/media/
files/nc111nt.zip.
```
### OfficeMalScanner
```
OfficeMalScanner is a free command-line tool for finding malicious
code in Microsoft Office documents. It locates shellcode, embedded PE
files, and OLE streams in Excel, Word, and PowerPoint documents, and
can decompress the newer format of Microsoft Office documents. We
recommend running OfficeMalScanner with the scan and brute options
on pre–Office 2007 documents and with the inflate option on post–
Office 2007 documents. You can download OfficeMalScanner from
http://www.reconstructer.org/.
```
### OllyDbg
```
OllyDbg is one of the most widely used debuggers for malware analysis.
We discuss OllyDbg extensively throughout the book, and Chapter 9 provides
an in-depth introduction to the tool. OllyDbg is a user-mode x86
debugger with a GUI. Several plug-ins are available for OllyDbg, such as
OllyDump for use while unpacking (discussed in Chapter 18). You can
download OllyDbg for free from http://www.ollydbg.de/.
```
### OSR Driver Loader
```
OSR Driver Loader is a freely available tool for loading a device driver
into memory. It is a GUI-based tool used for easily loading and starting
a driver without rebooting. This is useful when you are dynamically
Tools for Malware Analysis 471
analyzing a malicious device driver and don’t have the installer. We discuss
the OSR Driver Loader tool in Chapter 10. You can download it
from http://www.osronline.com/.
```
### PDF Dissector
```
PDF Dissector is a commercial GUI-based PDF analysis tool that graphically
parses PDF elements and automatically decompresses objects,
making it easy to extract malicious JavaScript. The program includes a
JavaScript deobfuscator and interpreter to help you understand and
execute malicious scripts. PDF Dissector can also be used to identify
known vulnerabilities. This tool is available for purchase from http://
www.zynamics.com/.
```
### PDF Tools
```
PDF Tools is the classic tool kit for PDF analysis. The tool kit consists of
two tools: pdfid.py and pdf-parser.py. pdfid.py scans a PDF for objects and
tells you if it thinks a PDF contains JavaScript. Since most malicious PDFs
use JavaScript, this information can help you quickly identify potentially
risky PDFs. pdf-parser.py helps you examine the contents and important
objects of a PDF file without rendering it. You can download the PDF
tools for free from http://blog.didierstevens.com/programs/pdf-tools/.
```
### PE Explorer
```
PE Explorer is a useful tool for viewing the PE header, sections, and
import/export tables. It is more powerful than PEview because it allows
you to edit structures. PE Explorer contains static unpackers for UPX-,
Upack-, and NsPack-compressed files. This unpacking feature is seamless
and saves a lot of time. You simply load the packed binary into PE
Explorer, and it automatically unpacks the file. You can download a trial
version or purchase the commercial version of PE Explorer from http://
www.heaventools.com/.
```
### PEiD
```
PEiD is a free static analysis tool used for packer and compiler detection.
It includes more than 600 signatures for detecting packers, cryptors, and
compilers in PE format files. PEiD also has plug-ins available for download,
the most useful of which is Krypto ANALyzer (KANAL). KANAL
can be used to find common cryptographic algorithms in PE files and
provides the ability to export the information to IDA Pro. We discuss
PEiD in Chapters 1, 13, and 18. Although the PEiD project has been
discontinued, you should still be able to download the tool from http://
www.peid.info/.
```
### PEview
```
PEview is a freely available tool for viewing the PE file structure. You can
view the PE header, individual sections, and the import/export tables.
We use PEview throughout the book and discuss it in Chapter 1. You can
download PEview from http://www.magma.ca/~wjr/.
```
### Process Explorer
```
Process Explorer is a powerful task manager that is used in dynamic analysis
to provide insight into processes currently running on a system. Process
Explorer can show you the DLLs for individual processes, handles,
events, strings, and so on. We discuss Process Explorer in Chapter 3. You
can download Process Explorer as part of the Sysinternals Suite of tools
from http://www.sysinternals.com/.
```
### Process Hacker
```
Process Hacker is a powerful task manager similar to Process Explorer,
but with many added features. It can scan for strings and regular expressions
in memory, inject or unload a DLL, load a driver, create or start
a service, and so on. You can download Process Hacker from http://
processhacker.sourceforge.net/.
```
### Process Monitor
```
Process Monitor (procmon) is a dynamic analysis tool useful for viewing
real-time filesystem, registry, and process activity. You can filter its output
to remove the noise. We discuss Process Monitor in Chapter 3. You can
download Process Monitor as part of the Sysinternals Suite of tools from
http://www.sysinternals.com/.
```
### Python
```
The Python programming language allows you quickly code tasks when
performing malware analysis. Throughout the book and labs, we use
Python. As discussed in Chapters 5 and 9, IDA Pro and Immunity Debugger
have built-in Python interpreters, allowing you to quickly automate
tasks or change the interface. We recommend learning Python and
installing it on your analysis machine. Download Python for free from
http://www.python.org/.
```
### Regshot
```
Regshot is a dynamic analysis tool that allows you to take and compare
two registry snapshots. To use it, you simply take a snapshot of the registry,
run the malware, wait for it to finish making any system changes, take
the second snapshot, and then compare the two. Regshot can also be
used for taking and comparing two snapshots of any filesystem directory
you specify. You can download Regshot for free from http://sourceforge
.net/projects/regshot/.
```
### Resource Hacker
```
Resource Hacker is a useful static analysis utility for viewing, renaming,
modifying, adding, deleting, and extracting resources for PE-formatted
binaries. The tool works with both x86 and x64 architectures. Because
malware often extracts more malware, a DLL, or a driver from its resource
section at runtime, we find this tool useful for extracting those sections
easily without running the malware. We discuss Resource Hacker in
Chapter 1 and the Chapter 12 labs. You can download Resource Hacker
from http://www.angusj.com/resourcehacker/.
```
### Sandboxes
```
Many sandboxes are publicly available, and you can also write your own.
Public sandboxes are a decent choice because they are always being
developed in an effort to stay on top of the market. We demonstrate
GFI Sandbox in Chapter 3, but there are many others, including Joe
Sandbox, BitBlaze, Comodo, ThreatExpert, Anubis, Norman, Cuckoo,
Zero Wine, Buster Sandbox, and Minibis. As with hex editors, everyone
has a preference, so try a few to see what works for you.
Sandboxie and Buster Sandbox Analyzer
Sandboxie is a program that runs programs in an isolated environment
to prevent them from making permanent changes to your system. Sandboxie
was designed to allow secure web browsing, but its sandbox aspect
makes it useful for malware analysis. For example, you can use it to capture
filesystem and registry accesses of the program you are sandboxing.
Buster Sandbox Analyzer (BSA) can be used with Sandboxie to provide
automated analysis and reporting. Sandboxie and BSA can be downloaded
from http://www.sandboxie.com/ and http://bsa.isoftware.nl/.
```
### Snort
```
Snort is the most popular open source network intrusion detection system
(IDS). We discuss writing network-based signatures for Snort in
Chapter 14. Snort can be run actively or offline against packet captures.
If you write network signatures for malware, using Snort to test them is a
good place to start. You can download Snort from http://www.snort.org/.
```
### Strings
```
Strings is a useful static analysis tool for examining ASCII and Unicode
strings in binary data. Using Strings is often a quick way to get a highlevel
overview of malware capability, but the program’s usefulness can be
thwarted by packing and string obfuscation. We discuss Strings in Chapter
1. You can download Strings as part of the Sysinternals Suite of tools
from http://www.sysinternals.com/.
```
### TCPView
```
TCPView is a tool for graphically displaying detailed listings of all TCP
and UDP endpoints on your system. This tool is useful in malware analysis
because it allows you to see which process owns a given endpoint.
TCPView can help you track down a process name when your analysis
machine connects over a port and you have no idea which process is
responsible (as often happens with process injection, as discussed in
Chapter 12). You can download TCPView as part of the Sysinternals
Suite of tools from http://www.sysinternals.com/.
```
### The Sleuth Kit
```
The Sleuth Kit (TSK) is a C library and set of command-line tools for
forensic analysis that can be used to find alternate data streams and files
hidden by rootkits. TSK does not rely on the Windows API to process
NTFS and FAT filesystems. You can run TSK on Linux or using Cygwin in
Windows. You can download TSK for free from http://www.sleuthkit.org/.
```
### Tor
```
Tor is a freely available onion routing network, allowing you to browse
anonymously over the Internet. We recommend using Tor whenever
conducting research during analysis, such as checking IP addresses,
performing Internet searches, accessing domains, or looking for any
information you might not want exposed. We don’t generally recommend
letting malware connect over a network, but if you do, you should
use a technology like Tor. After you install Tor, and before you start
browsing, visit a site like http://whatismyipaddress.com/ to confirm that
the IP returned by the website is not your IP address. Tor can be downloaded
for free from https://www.torproject.org/.
```
### Truman
```
Truman is a tool for creating a safe environment without using virtual
machines. It consists of a Linux server and a client machine running
Windows. Like INetSim, Truman emulates the Internet, but it also provides
functionality to easily grab memory from the Windows machine
and reimage it quickly. Truman comes with scripts to emulate services
and perform analysis on Linux. Even though this tool is no longer in
development, it can help you understand how to set up your own baremetal
environment. You can download Truman for free from http://
www.secureworks.com/research/tools/truman/.
```
### WinDbg
```
WinDbg is the most popular all-around debugger, distributed freely by
Microsoft. You can use it to debug user-mode, kernel-mode, x86, and x64
malware. WinDbg lacks OllyDbg’s robust GUI, providing a commandline
interface instead. In Chapter 10, we focus on the kernel-mode usage
of WinDbg. Many malware analysts choose to use OllyDbg for user-mode
debugging and WinDbg for kernel debugging. WinDbg can be downloaded
independently or as part of the Windows SDK from http://msdn.microsoft.com/.
```
### Wireshark
```
Wireshark is an open source network packet analyzer and useful tool for
dynamic analysis. You can use it to capture network traffic generated by
malware and to analyze many different protocols. Wireshark is the most
popular freely available tool for packet capturing and has an easy-to-use
GUI. We discuss Wireshark usage in Chapter 3. You can download Wireshark
from http://www.wireshark.org/.
```
### UPX
```
Ultimate Packer for eXecutables (UPX) is the most popular packer used
by malware authors. In Chapters 1 and 18, we discuss how to automatically
and manually unpack malware that uses UPX. If you encounter this
packer in the wild, try to unpack the malware with upx –d. You can download
this packer from http://upx.sourceforge.net/.
```
### VERA
```
Visualizing Executables for Reversing and Analysis (VERA) is a tool for
visualizing compiled executables for malware analysis. It uses the Ether
Tools for Malware Analysis 475
framework to generate visualizations based on dynamic trace data to
help with analysis. VERA gives you a high-level overview of malware and
can help with unpacking. It can also interface with IDA Pro to help you
browse between the VERA graphs and IDA Pro disassembly. You can
download VERA from http://www.offensivecomputing.net/.
```
### VirusTotal
```
VirusTotal is an online service that scans malware using many different
antivirus programs. You can upload a file directly to VirusTotal, and it
will check the file with more than 40 different antivirus engines. If you
don’t want to upload your malware, you can also search the MD5 hash to
see if VirusTotal has seen the sample before. We discuss VirusTotal at the
start of Chapter 1 since it is often a useful first step during malware analysis.
You can access VirusTotal at http://www.virustotal.com/.
```
### VMware Workstation
```
VMware Workstation is a popular desktop virtualization product. There
are many alternatives to VMware, but we use it in this book due to its
popularity. Chapter 2 highlights many VMware features, such as virtual
networking, snapshotting (which allows you to save the current state of a
virtual machine), and cloning an existing virtual machine. You can purchase
VMware Workstation from http://www.vmware.com/ or download
VMware Player (with limited functionality) for free from the same site.
```
### Volatility Framework
```
The Volatility Framework is an open source collection of tools written in
Python for analyzing live memory captures. This suite of tools is useful
for malware analysis, as you can use it to extract injected DLLs, perform
rootkit detection, find hidden processes, and so on. This tool suite has
many users and contributors, so new capabilities are constantly being
developed. You can download the latest version from http://code.google
.com/p/volatility/.
```
### YARA
```
YARA is an open source project used to identify and classify malware
samples that will allow you to create descriptions of malware families
based on strings or any other binary patterns you find in them. These
descriptions are called rules, and they consist of a set of strings and logic.
Rules are applied to binary data like files or memory in order to classify a
sample. This tool is useful for creating your own custom antivirus-like
software and signatures. You can download YARA for free from http://
code.google.com/p/yara-project/.
```
### Zero Wine
```
Zero Wine is an open source malware sandbox that is distributed as a virtual
machine running Debian Linux. Malware samples are executed using
Zero Wine to emulate the Windows API calls, and the calls are logged to
report on malicious activity. Zero Wine can even catch and defeat certain
anti-virtual machine, anti-debugging, and anti-emulation techniques. You
can download Zero Wine from http://zerowine.sourceforge.net/.
``` 
