C:\Windows\system32\cmd.exe /C "cd . && C:\PROGRA~1\LLVM\bin\CLANG_~1.EXE -nostartfiles -nostdlib -O2 -DNDEBUG -D_DLL -D_MT -Xclang --dependent-lib=msvcrt -flto=thin -Xlinker /subsystem:windows  -Xlinker "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"" -fuse-ld=lld-link CMakeFiles/goodnight-gui.dir/gui/gui.cpp.obj CMakeFiles/goodnight-gui.dir/external/RmlUi/Backends/RmlUi_Platform_GLFW.cpp.obj CMakeFiles/goodnight-gui.dir/external/RmlUi/Backends/RmlUi_Renderer_GL3.cpp.obj CMakeFiles/goodnight-gui.dir/external/RmlUi/Backends/RmlUi_Backend_GLFW_GL3.cpp.obj -o goodnight-gui.exe -Xlinker /MANIFEST:EMBED -Xlinker /implib:goodnight-gui.lib -Xlinker /pdb:goodnight-gui.pdb -Xlinker /version:0.0  -LJ:/Projects/GoodnightLaptop/lib/external/prebuilts goodnight-lib.lib  external/freetype/freetype.lib  -lglfw3_mt.lib  -lwevtapi.lib  -lSetupapi.lib  -lNewdev.lib  external/RmlUi/Source/Debugger/rmlui_debugger.lib  external/RmlUi/Source/Core/rmlui.lib  external/freetype/freetype.lib  external/glfw/src/glfw3.lib  -lkernel32 -luser32 -lgdi32 -lwinspool -lshell32 -lole32 -loleaut32 -luuid -lcomdlg32 -ladvapi32 -loldnames  && cd ."