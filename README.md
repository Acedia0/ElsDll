This is a Lua code injector created using the MinHook library.
Elsdll was originally created to inject code into the various versions of Elsword x64, but it can very easily be adapted for most Lua-based games.


Tutorial on injecting .lua scripts into Elsrift x64 :

1) Download the ElsDll project
2) Build the project to obtain the .dll to be injected

3) Convert the .lua script you want to run into LuaJit 2.1.0-beta3 x64 bytecode
	a. You can do this with the following tool: https://github.com/ScriptTiger/LuaJIT-For-Windows\n
	b. Rename your .lua script to Script.lua and place it in the same folder as LuaJIT-For-Windows.cmd\n
	c. Run LuaJIT-For-Windows.cmd with the following command: luajit -b Script.lua Script.out\n
	d. Move the Script.out file to the same folder as x2.exe.\n

4) Inject the .dll when x2.exe starts up using your favourite injector.

   Warning: You will have to bypass anticheats with your own methods.

Good luck!


Here are a few links to help you understand how it works:
- https://colton1skees.github.io/posts/LuaReversal.html
- https://nickcano.com/hooking-luajit/
- http://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html
- https://www.youtube.com/watch?v=qEbPCIFtyOs
