/*

-----------
MIT License
-----------

Copyright (c) 2022 Delicious Lines

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.

*/


#include <stdint.h>
#include <string.h>

#define STB_SPRINTF_IMPLEMENTATION
#include "stb_sprintf.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>    // For EnumProcesses().
#include <shlwapi.h>  // For file path stuff.
#include <shellapi.h> // For tray icon stuff.

#pragma comment(lib, "Kernel32")
#pragma comment(lib, "User32")
#pragma comment(lib, "Shlwapi")
#pragma comment(lib, "Shell32")
#pragma comment(lib, "Advapi32") // Required for registry stuff.


#define true  1
#define false 0

typedef uint8_t  b8;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#define cast(_x, _type) ((_type)(_x))

#define KB(_x) ((_x)   * 1024)
#define MB(_x) (KB(_x) * 1024)

typedef struct
{
    void* data;
    u64 size;
} Memory;

typedef struct
{
    char* data;
    s32 count;
} String;

#define STRING(_v) {.data = _v, .count = sizeof(_v) - 1}


// Globals. START
const u64 TMP_MEMORY_SIZE = MB(10);
Memory tmp_memory = {};
u64 tmp_memory_offset = 0;

Memory blacklist_memory = {};
String blacklist = {};
u64 blacklist_last_modified = 0;

const u32 WM_INTERACT_WITH_TRAY_ICON = WM_USER;

const String REGISTRY_KEY_PATH = STRING("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
const String REGISTRY_KEY_NAME = STRING("win32_process_killer");
const u16*   REGISTRY_KEY_NAME_UTF16 = L"win32_process_killer";

const String LIST_NAME = STRING("blacklist.txt");

const u8 SHOULD_RUN = 0x01;
u8 global_flags = SHOULD_RUN;
// Globals. END


inline String String_(char* c_string)
{
    String string = {.data = c_string, .count = strlen(c_string)};
    return string;
}

inline Memory reallocate(Memory data, u64 new_size)
{
    if(data.size >= new_size) return data;
    
    if(data.data) VirtualFree(data.data, 0, MEM_RELEASE);
    
    data.size = new_size;
    data.data = VirtualAlloc(NULL, new_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    return data;
}

inline void* tallocate(u64 size)
{
    void* data = tmp_memory.data + tmp_memory_offset;
    tmp_memory_offset += size;
    
    return data;
}

inline void treset()
{
    tmp_memory_offset = 0;
}

inline b8 strings_match(String* a, String* b)
{
    if(a->count != b->count) return false;
    return (memcmp(a->data, b->data, a->count) == 0);
}

String utf16_to_utf8(u16* input, u32 num_characters_in_input)
{
    u32 output_size = num_characters_in_input * 4 + 1;
    
    u8* output = tallocate(output_size); // '+ 1' to easily convert to a C string.
    String result = {.data = cast(output, char*)};
    memset(result.data, 0, output_size);
    
    u32 num_utf16_characters_decoded_so_far = 0;
    while(num_utf16_characters_decoded_so_far < num_characters_in_input)
    {
        u32 codepoint = 0;
        u16 value = *input;
        
        // Retrieve codepoint. START
        if(value < 0xd800 || (value >= 0xe000 && value <= 0xffFF))
        {
            codepoint = value;
            input++;
        }
        else
        {
            u16 leading_surrogate  = input[0];
            u16 trailing_surrogate = input[1];
            
            if((leading_surrogate & 0b1111110000000000) == 0b1101100000000000 && (trailing_surrogate & 0b1111110000000000) == 0b1101110000000000)
            {
                codepoint = (cast(leading_surrogate - 0xd800, u32) << 10) | (trailing_surrogate - 0xdc00);
                input += 2;
            }
            else input++;
        }
        // Retrieve codepoint. END
        
        // Convert codepoint to UTF-8. START
        if(codepoint < 0x80)
        {
            output[0] = codepoint;
            output++;
            result.count++;
        }
        else if(codepoint < 0x800)
        {
            output[0] = 0b11000000 | (codepoint >> 6);
            output[1] = 0b10000000 | (codepoint & 0b111111);
            
            output       += 2;
            result.count += 2;
        }
        else if(codepoint < 0x10000)
        {
            output[0] = 0b11100000 | (codepoint >> 12);
            output[1] = 0b10000000 | ((codepoint >> 6) & 0b111111);
            output[2] = 0b10000000 | (codepoint & 0b111111);
            
            output       += 3;
            result.count += 3;
        }
        else
        {
            output[0] = 0b11110000 | (codepoint >> 18);
            output[1] = 0b10000000 | ((codepoint >> 12) & 0b111111);
            output[2] = 0b10000000 | ((codepoint >> 6) & 0b111111);
            output[3] = 0b10000000 | (codepoint & 0b111111);
            
            output       += 4;
            result.count += 4;
        }
        // Convert codepoint to UTF-8. END
        
        num_utf16_characters_decoded_so_far++;
    }
    
    return result;
}

u16* utf8_to_utf16(String utf8)
{
    u64 result_size = utf8.count * sizeof(u16) * 2 + 2;
    u16* result = tallocate(result_size);
    memset(result, 0, result_size);
    
    u16* output = result;
    
    char* input = utf8.data;
    char* limit = utf8.data + utf8.count;
    
    while(input < limit)
    {
        u32 codepoint = 0;
        
        // Retrieve codepoint. START
        if((input[0] & 0b10000000) == 0)
        {
            codepoint = input[0];
            input++;
        }
        else if((input[0] & 0b11100000) == 0b11000000)
        {
            codepoint = (cast(input[0] & 0b11111, u32) << 6) | (input[1] & 0b111111);
            input += 2;
        }
        else if((input[0] & 0b11110000) == 0b11100000)
        {
            codepoint = (cast(input[0] & 0b1111, u32) << 12) | (cast(input[1] & 0b111111, u32) << 6) | (input[2] & 0b111111);
            input += 3;
        }
        else
        {
            codepoint = (cast(input[0] & 0b11111, u32) << 18) | (cast(input[1] & 0b111111, u32) << 12) | (cast(input[2] & 0b111111, u32) << 6) | (input[3] & 0b111111);
            input += 4;
        }
        // Retrieve codepoint. END
        
        // Convert codepoint to UTF-16. START
        if(codepoint < 0xd800 || (codepoint >= 0xe000 && codepoint <= 0xffFF))
        {
            *output = codepoint;
            output++;
        }
        else
        {
            codepoint -= 0x10000;
            
            output[0] = (codepoint >> 10) + 0xd800;
            output[1] = (codepoint & 0b1111111111) + 0xdc00;
            output += 2;
        }
        // Convert codepoint to UTF-16. END
    }
    
    return result;
}

inline u16* get_full_exe_filepath_utf16(u32* num_characters_in_filepath)
{
    const u32 MAX_CHARACTERS_IN_FILEPATH = 2048;
    u16* utf16_filepath = tallocate((MAX_CHARACTERS_IN_FILEPATH + 1) * sizeof(u16) * 2);
    
    u32 num_characters = GetModuleFileNameW(NULL, utf16_filepath, MAX_CHARACTERS_IN_FILEPATH);
    if(num_characters_in_filepath) *num_characters_in_filepath = num_characters;
    
    return utf16_filepath;
}

String get_exe_filepath()
{
    u32 num_characters_in_filepath = 0;
    u16* utf16_filepath = get_full_exe_filepath_utf16(&num_characters_in_filepath);
    PathRemoveFileSpecW(utf16_filepath);
    
    num_characters_in_filepath = wcslen(utf16_filepath);
    
    String filepath = utf16_to_utf8(utf16_filepath, num_characters_in_filepath);
    return filepath;
}

inline String get_full_exe_filepath()
{
    u32 num_characters_in_filepath = 0;
    u16* utf16_filepath = get_full_exe_filepath_utf16(&num_characters_in_filepath);
    
    String filepath = utf16_to_utf8(utf16_filepath, num_characters_in_filepath);
    return filepath;
}

void maybe_load_blacklist()
{
    /////////////////////////////////////////////////////////////////////////////////////////////
    // NOTE: we only load the blacklist if it has been modified since the last time we loaded it.
    /////////////////////////////////////////////////////////////////////////////////////////////

    // Get the black list filepath. START
    String exe_filepath = get_exe_filepath();
    
    String filepath = {.data = tallocate(exe_filepath.count + LIST_NAME.count + 8)};
    stbsp_sprintf(filepath.data, "%s/%s", exe_filepath.data, LIST_NAME.data);
    filepath.count = strlen(filepath.data);
    
    u16* utf16_filepath = utf8_to_utf16(filepath);
    // Get the black list filepath. END
    
    
    void* file = CreateFileW(utf16_filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(file != INVALID_HANDLE_VALUE)
    {
        u64 file_last_modified = 0;
        GetFileTime(file, NULL, NULL, cast(&file_last_modified, FILETIME*));
    
        u64 file_size = 0;
        GetFileSizeEx(file, cast(&file_size, LARGE_INTEGER*));
        
        
        if(file_last_modified != blacklist_last_modified || blacklist.count != file_size)
        { // The list has been modified since last time we loaded it, we need to reload it.
            blacklist_memory = reallocate(blacklist_memory, file_size);
            blacklist.data = blacklist_memory.data;
            
            unsigned long num_bytes_read;
            ReadFile(file, blacklist.data, file_size, &num_bytes_read, NULL);
            blacklist.count = num_bytes_read;
            
            blacklist_last_modified = file_last_modified;
        }
        
        
        CloseHandle(file);
    }
}

b8 do_we_run_at_startup()
{
    HKEY key = NULL;
    LSTATUS status = RegCreateKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY_PATH.data, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key, NULL);
    if(status != ERROR_SUCCESS) return false;
    
    const u32 VALUE_NAME_MAX_SIZE = 256  * sizeof(u16);
    const u32 VALUE_DATA_MAX_SIZE = 2048 * sizeof(u16);
    
    u8 value_name[VALUE_NAME_MAX_SIZE];
    u8 value_data[VALUE_DATA_MAX_SIZE];
    
    u32 index = 0;
    while(1)
    {
        DWORD name_buffer_size = VALUE_NAME_MAX_SIZE;
        DWORD data_buffer_size = VALUE_DATA_MAX_SIZE;
        status = RegEnumValueW(key, index, cast(value_name, u16*), &name_buffer_size, NULL, NULL, value_data, &data_buffer_size);
        index++;
        
        if(status == ERROR_NO_MORE_ITEMS) break;
        else if(status != ERROR_SUCCESS) continue;
        
        s32 num_characters_in_utf16_name = wcslen(cast(value_name, u16*));
        String name = utf16_to_utf8(cast(value_name, u16*), num_characters_in_utf16_name);
        
        if(strings_match(cast(&REGISTRY_KEY_NAME, String*), &name))
        {
            /////////////////////////////////////////////////////////////////////////////
            // NOTE: if the key data does not match the executable filepath we delete it.
            /////////////////////////////////////////////////////////////////////////////
        
            s32 num_characters_in_utf16_filepath = wcslen(cast(value_data, u16*));
            String filepath = utf16_to_utf8(cast(value_data, u16*), num_characters_in_utf16_filepath);
            // Account for the '"' surrounding the filepath.
            filepath.data++;
            filepath.count -= 2;
            ////////////////////////////////////////////////
        
            String exe_filepath = get_full_exe_filepath();
            
            if(strings_match(&filepath, &exe_filepath))
            {
                RegCloseKey(key);
                return true; // The filepath contained in the key value is correct.
            }
            
            RegDeleteKeyValueW(key, NULL, REGISTRY_KEY_NAME_UTF16); // The filepath contained in the key is out of date. No need to keep it around.
            RegCloseKey(key);
            
            return false;
        }
    }
    
    RegCloseKey(key);
    return false;
}

void set_run_at_startup(b8 run_at_startup)
{
    HKEY key = NULL;
    LSTATUS status = RegCreateKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY_PATH.data, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &key, NULL);
    if(status != ERROR_SUCCESS) return;
    
    u16* utf16_key_name = utf8_to_utf16(REGISTRY_KEY_NAME);
    
    if(run_at_startup)
    {
        ////////////////////////////////////////////////////////////////////////////////////////////////////////
        // NOTE: we surround the filepath with '"' so that spaces in directory names are properly accounted for.
        ////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        String filepath = get_full_exe_filepath();
        String filepath_string = {.data = tallocate(filepath.count + 2 + 1), .count = filepath.count + 2};
        stbsp_sprintf(filepath_string.data, "\"%s\"", filepath.data);
        
        u16* utf16_filepath = utf8_to_utf16(filepath_string);
        DWORD filepath_size = 0;
        u16* c = utf16_filepath;
        while(*c)
        {
            filepath_size += sizeof(u16);
            c++;
        }
        
        status = RegSetKeyValueW(key, NULL, REGISTRY_KEY_NAME_UTF16, REG_SZ, utf16_filepath, filepath_size + sizeof(u16));
    }
    else
    {
        status = RegDeleteKeyValueW(key, NULL, utf16_key_name);
    }
    
    RegCloseKey(key);
}

LRESULT window_message_callback(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    if(message == WM_INTERACT_WITH_TRAY_ICON)
    {
        int sub_message = LOWORD(lparam);
        
        if(sub_message == WM_RBUTTONDOWN || sub_message == WM_LBUTTONDOWN)
        {
            // Draw and update menu. START
            HMENU menu = CreatePopupMenu();
            
            const u32 MENU_EXIT                      = 0x01;
            const u32 MENU_RUN_AT_STARTUP            = 0x02;
            const u32 MENU_DO_NOT_RUN_AT_STARTUP     = 0x04;
            const u32 MENU_OPEN_BLACKLIST            = 0x08;
            const u32 MENU_CREATE_AND_OPEN_BLACKLIST = 0x10;
            
            // Get the black list filepath. START
            String exe_filepath = get_exe_filepath();
            
            String blacklist_filepath = {.data = tallocate(exe_filepath.count + LIST_NAME.count + 8)};
            stbsp_sprintf(blacklist_filepath.data, "%s/%s", exe_filepath.data, LIST_NAME.data);
            blacklist_filepath.count = strlen(blacklist_filepath.data);
            
            u16* utf16_blacklist_filepath = utf8_to_utf16(blacklist_filepath);
            // Get the black list filepath. END
            
            b8 run_at_startup   = do_we_run_at_startup();
            b8 blacklist_exists = PathFileExistsW(utf16_blacklist_filepath);
            
            AppendMenu(menu, MF_STRING | MF_GRAYED, 0, "Process Killer");
            AppendMenu(menu, MF_SEPARATOR, 0, NULL);
            
            if(run_at_startup) AppendMenu(menu, MF_STRING, MENU_DO_NOT_RUN_AT_STARTUP, "Do not run at start-up");
            else               AppendMenu(menu, MF_STRING, MENU_RUN_AT_STARTUP,        "Run at start-up");
            
            if(blacklist_exists) AppendMenu(menu, MF_STRING, MENU_OPEN_BLACKLIST, "Open black list");
            else                 AppendMenu(menu, MF_STRING, MENU_CREATE_AND_OPEN_BLACKLIST, "Create and open black list");
            
            AppendMenu(menu, MF_STRING, MENU_EXIT, "Exit");
            
            POINT mouse = {};
            GetCursorPos(&mouse);
            
            SetForegroundWindow(window);
            u32 menu_item = TrackPopupMenu(menu, TPM_NONOTIFY | TPM_RETURNCMD, mouse.x, mouse.y, 0, window, NULL);
            if(menu_item == MENU_EXIT)
            {
                global_flags &= ~SHOULD_RUN;
            }
            else if(menu_item == MENU_RUN_AT_STARTUP)
            {
                set_run_at_startup(true);
            }
            else if(menu_item == MENU_DO_NOT_RUN_AT_STARTUP)
            {
                set_run_at_startup(false);
            }
            else if(menu_item == MENU_OPEN_BLACKLIST)
            {
                ShellExecuteW(NULL, L"open", utf16_blacklist_filepath, NULL, NULL, SW_SHOWNORMAL);
            }
            else if(menu_item == MENU_CREATE_AND_OPEN_BLACKLIST)
            {
                void* file = CreateFileW(utf16_blacklist_filepath, 0, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
                CloseHandle(file);
                
                ShellExecuteW(NULL, L"open", utf16_blacklist_filepath, NULL, NULL, SW_SHOWNORMAL);
            }
            
            DestroyMenu(menu);
            // Draw and update menu. END
        }
        
        return 0;
    }

    return DefWindowProcA(window, message, wparam, lparam);
}

int WinMain()
{
    const u32 MAX_PROCESSES_TO_LIST = 1024;
    DWORD process_ids[MAX_PROCESSES_TO_LIST];
    
    tmp_memory = reallocate(tmp_memory, TMP_MEMORY_SIZE);
    
    
    // Create a window. START
    const char* WINDOW_TITLE = "Win32 Process Killer";
    
    WNDCLASSA window_settings = {
        .lpfnWndProc   = window_message_callback,
        .style         = CS_OWNDC,
        .lpszClassName = "window_settings"
    };
    
    if(FindWindowA(window_settings.lpszClassName, WINDOW_TITLE))
    { // An instance of this program is already running, no need to run an additional one.
        return 0;
    }
    
    RegisterClassA(&window_settings);
    
    HWND window = CreateWindowA(
        window_settings.lpszClassName, WINDOW_TITLE, WS_POPUP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, NULL, NULL, NULL
    );
    if(!window) return 0;
    // Create a window. END
    
    // Create a tray icon. START
    HICON logo_icon = LoadImageA(GetModuleHandleA(NULL), "LOGO", IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED);
    
    NOTIFYICONDATAA tray_icon = {
        .cbSize = sizeof(NOTIFYICONDATAA),
        
        .hWnd             = window,
        .hIcon            = logo_icon,
        .uCallbackMessage = WM_INTERACT_WITH_TRAY_ICON,
        .uFlags           = NIF_MESSAGE | NIF_ICON | NIF_TIP
    };
    
    strcpy(tray_icon.szTip, "Process Killer");
    
    Shell_NotifyIconA(NIM_ADD, &tray_icon);
    // Create a tray icon. END
    
    
    while(global_flags & SHOULD_RUN)
    {
        treset();
        
        
        // Handle events. START
        MSG message;
        while(PeekMessageA(&message, window, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&message);
            DispatchMessage(&message);
        }
        // Handle events. END
        
        
        maybe_load_blacklist();
        
    
        DWORD result_size;
        b8 ok = EnumProcesses(process_ids, MAX_PROCESSES_TO_LIST * sizeof(DWORD), &result_size);
        if(ok)
        {
            // Go through processes and take down the ones on the black list. START
            u32 processes_list_count = result_size / sizeof(DWORD);
            for(u32 process_index = 0; process_index < processes_list_count; process_index++)
            {
                DWORD process_id = process_ids[process_index];
                
                HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, false, process_id);
                if(process == NULL) continue;
                
                const u32 MAX_CHARACTERS_IN_NAME = 512;
                
                const u32 UTF16_NAME_MAX_SIZE = MAX_CHARACTERS_IN_NAME * sizeof(u16) * 2;
                u8 utf16_name[UTF16_NAME_MAX_SIZE];
                
                DWORD num_characters_in_name = GetModuleBaseNameW(process, NULL, cast(utf16_name, u16*), UTF16_NAME_MAX_SIZE);
                if(!num_characters_in_name) goto done_with_this_process;
                
                String name = utf16_to_utf8(cast(utf16_name, u16*), num_characters_in_name);
                
                // Go through the black list and kill the process if a match is found between this name and one of the black list's. START
                char* c     = blacklist.data;
                char* limit = blacklist.data + blacklist.count;
                
                String blacklist_name = {.data = c};
                while(c < limit)
                {
                    char character = *c;
                    if(character == '\n' || character == '\r')
                    {
                        if(strings_match(&blacklist_name, &name))
                        {
                            TerminateProcess(process, 0);
                            goto done_with_this_process;
                        }
                        
                        blacklist_name.data  = c + 1;
                        blacklist_name.count = 0;
                    }
                    else blacklist_name.count++;
                    
                    c++;
                }
                
                if(strings_match(&blacklist_name, &name)) TerminateProcess(process, 0);
                // Go through the black list and kill the process if a match is found between this name and one of the black list's. END
                
                done_with_this_process:;
                CloseHandle(process);
            }
            // Go through processes and take down the ones on the black list. END
        }
    
        Sleep(100);
    }
    
    // Remove the tray icon.
    tray_icon.uFlags = 0;
    Shell_NotifyIconA(NIM_DELETE, &tray_icon);
    ////////////////////////

    return 0;
}