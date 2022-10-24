# Automatic process killer for Windows
This is a simple utility that kills unwanted processes at any time.

## How to use it
Simply run ``pk.exe``. You can access the program through a tray icon. By default the program does not run at startup, you can modify this through the tray menu.

To tell the program which processes to kill, make a list of executables names (case-sensitivity matters) in a file named ``blacklist.txt`` and put this file at the program location (some/path/pk.exe).
One line in this list corresponds to one process to kill. The program automatically reloads the list when it is modified.

## How to compile it yourself
Just run your C compiler on ``entry_point.c``. Do not forget to include ``resources.res`` when linking.

MSVC example: ``cl /O2 /TC /D_CRT_SECURE_NO_WARNINGS entry_point.c /Fepk.exe /link resources.res``

## License
This code is placed under the MIT license. You can check the license details in ``entry_point.c``. This code makes use of STB sprintf (https://github.com/nothings/stb/blob/master/stb_sprintf.h) which is also placed under the MIT license.
