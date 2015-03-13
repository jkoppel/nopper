One of the best ways to understand what a piece of code does is to see what happens when it doesn't run.

When you have the source code, you comment lines out. With binaries, you replace the instructions with NOP.

You can't patch a file from IDA, but with Nopper, you can simulate the effect.

**This project has been succeeded**

REProgram operates by patching the process after it has been loaded, contains a superset of the functionality of Nopper, and is far faster. It is available from http://www.hex-rays.com/contest2011/reprogram.zip .

# Usage
After installation, highlight the region of code you wish to disable, and then run the plugin from the menu, or press Alt+F2. When you run the program in the debugger, that region will then be skipped over.

You can reenable the code in the exact same way.

# Tips & Tricks

Minimize IDA after running your program, or else focus will return to IDA every time a nopped section is hit.
Nopper works by marking a region as disabled, setting a breakpoint at the start of the region, and jumping to the end whenever the breakpoint is hit. By toggling only the breakpoint, you can easily reenable and redisable an entire section.

Nopper is fast, but there is still overhead involved in using breakpoints. If you want to disable an instruction which is invoked thousands of times a second, you are best off actually patching the binary.

# Example

Normal execution of the program:



Disabling a function with Nopper:



Execution of the program with that function disabled:

