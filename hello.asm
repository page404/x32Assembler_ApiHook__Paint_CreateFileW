.386  ;表示指令集,再往前就是 16位指令集了.
.model flat, stdcall  ;model flat :表示内存模型为 flat    stdcall:默认的调用约定,如果不在这里写,那么,每个函数我们都要自己写调用约定.
option casemap:none  ;区分大小写,如果不写这一行,不区分大小写.

;-------这里的路径必须是 RadASM 32位 软件的安装目录下的 include 跟 lib,要不然生成不了 exe 文件
;--inc相关
include C:\RadASM\masm32\include\windows.inc
include C:\RadASM\masm32\include\kernel32.inc
include C:\RadASM\masm32\include\user32.inc
include myres.inc

;--lib相关
includelib kernel32.lib
includelib user32.lib

.const  ;常量段,该段的内容是只读的.
  g_szHello db 'open Paint Soft first, then click left to hook Paint CreateFileW api, when save picture , pop MessageBox show save full path.', 0
  g_szTitle db 'Page404', 0

  g_szUsername db 'Backer', 0
  g_szPassword db 'Cracker', 0

  ;根据类名,查找对应的窗口句柄
  g_szClassName db 'MSPaintApp', 0   ;画图 类名

  g_szKernel32 db 'Kernel32', 0
  g_szUser32 db 'User32', 0

  g_szSleep db 'Sleep', 0
  g_szMsgBox db 'MessageBoxW', 0


.data
  g_hInst     dd 0
  ;长 jmp 的机器码是 e9,即占 5个字节 , 短 jmp 的机器码是 EB,即占 2个字节
  g_JmpCode   db 0e9h
  g_JmpOffset dd 0

.code

INJECTCODE_BEGIN:  ;---------------要注入到目标内存中代码的开始位置
g_lpMsgBox dd 0
InjectCode proc

  ;保存各寄存器环境变量
  pushad
  
  ;-----动态重定位(运行时(call NEXT)的地址 减去 编译时(offset)的地址),即相对偏移
  ;INJECTCODE_BEGIN 到 INJECTCODE_END 这段代码是注入到扫雷的内存当中去的,所以偏移地址跟我们自己的hello.exe肯定不一样,所以要用动态重定位的方式来计算偏移量
  ;并在下面调用系统的 LoadLibrary->GetProcAddress 得到 MessageBoxA 及 Sleep 等系统 api 的固定地址
  ;最后,将 相对偏移地址+固定地址,即是我们程序运行时,调用的系统api地址.
  ;这样处理,不管注入任何的exe中,都是计算要注入exe运行时所调用的系统api地址.
  call NEXT
NEXT:
  pop ebx
  sub ebx, offset NEXT
  
  push MB_OK
  push NULL
  mov eax, [esp+2ch]
  push eax
  push NULL
  call [offset g_lpMsgBox + ebx]

  ;还原各寄存器环境变量
  popad
  
  ;被 hook 替换掉的那一行代码,现在要写回去.
  mov   eax, 10362A5h
  
  ;------101d1a2h hook目标内存行的下一行地址.
  ; push + ret 相当于 jmp
  ;如果直接用 jmp ,那么还要计算代码的相对偏移地址.
  ;如果想用 jmp ,那么,得先把跳转地址存先存放到寄存器,再调用,如: mov ecx,101d1a2h  jmp ecx ,但是,必须确认 ecx 在后面是否有用到,如果用到了,值会被覆盖.
  push  101d1a2h
  ret

InjectCode endp
INJECTCODE_END:   ;---------------要注入到目标内存中代码的结束位置

Inject proc
  ;查找到的窗口句柄
  local @hWnd:HWND
  ;进程的标识符
  local @dwPID:DWORD
  ;打开进程的句柄
  local @hProcess:HANDLE
  ;所分配内存的基地址
  local @lpMem:LPVOID
  local @nInjectCodeSize:UINT
  local @dwOld:DWORD

  ;初始化初值为0(即错误值),这样,在退出程序时,检查函数EXIT_PROC:块就不会因为是随机值而判断错误
  xor eax, eax
  mov @hWnd, eax
  mov @hProcess, eax
  mov @lpMem, eax
  mov @nInjectCodeSize, eax

  ;调用 FindWindow api函数
  invoke FindWindow, offset g_szClassName, NULL
  .if eax == NULL
    jmp EXIT_PROC
  .endif
  mov @hWnd, eax

  ;调用 GetWindowThreadProcessId api函数
  invoke GetWindowThreadProcessId, @hWnd, addr @dwPID
  ;调用 OpenProcess api函数,建立两个进程之间的联系
  invoke OpenProcess, PROCESS_ALL_ACCESS, FALSE, @dwPID
  .if eax == NULL
    jmp EXIT_PROC
  .endif
  ;这里的 eax 为 OpenProcess 的函数返回值
  mov @hProcess, eax

  ;计算要注入到扫雷内存中的代码的长度
  mov @nInjectCodeSize, offset INJECTCODE_END - offset INJECTCODE_BEGIN
  ;调用 VirtualAllocEx api函数,开辟内存空间
  ;这里的 @hProcess 为查找到的窗口(即画图)的进程句柄,所以是在画图里面分配的内存空间
  invoke VirtualAllocEx, @hProcess, NULL, @nInjectCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE
  .if eax == NULL
    jmp EXIT_PROC
  .endif
  mov @lpMem, eax

  ;调用 VirtualProtect api函数,修改我们在画图中所分配内存的属性为 可读可写可执行
  ;下面的 mov g_lpMsgBox, eax 都修改了这一块内存中的数据,所以,这行代码要在他们之前执行.
  invoke VirtualProtect, INJECTCODE_BEGIN, @nInjectCodeSize, PAGE_EXECUTE_READWRITE, addr @dwOld
  ; check it

  ;------得到 Kernel32 中的 Sleep 函数的 地址
  ;调用 LoadLibrary api函数
  invoke LoadLibrary, offset g_szUser32
  ; check it
  ;调用 GetProcAddress api函数
  invoke GetProcAddress, eax, offset g_szMsgBox
  ; check it
  mov g_lpMsgBox, eax

  ;调用 WriteProcessMemory api函数,写入代码到画图的内存,代码的起始地址为 offset INJECTCODE_BEGIN,写入长度为 @nInjectCodeSize
  invoke WriteProcessMemory, @hProcess, @lpMem, offset INJECTCODE_BEGIN, @nInjectCodeSize, NULL
  .if eax == FALSE
    jmp EXIT_PROC
  .endif
  

  mov eax, @lpMem
  add eax, offset InjectCode - offset INJECTCODE_BEGIN
  ;101d19dh 地址为 writeFileW 的函数指针调用入口处地址.
  ;writeFilew函数指针调用入口处,在OD中占用5个字节的大小,所以 101d19dh + 5 表示下一条指令的地址(我们注入完自己的代码,要返回到的地址)
  mov esi, 101d19dh + 5
  sub eax, esi
  
  ;---- 往 101d19dh 地址写入 5个字节.
  ;第1个字节为 g_JmpCode 所占的1个字节,即 长 jmp 的机器码 e9
  ;后面的4个字节为 g_JmpOffset 所占的 4个字节.因为 g_JmpOffset变量 是紧接着定义在 g_JmpCode变量 的后面的.
  mov g_JmpOffset, eax
  invoke WriteProcessMemory, @hProcess, 101d19dh, offset g_JmpCode, 5, NULL
  .if eax == FALSE
    jmp EXIT_PROC
  .endif

EXIT_PROC:

;--------------因为该 api hook 的功能是保存图片时,弹出一个对话框,所以,只要注入进去后,不去释放这片内存空间,在每次保存图片的时候,都会调用我们写入的这块代码段.
;  .if @lpMem
;    invoke VirtualFreeEx, @hProcess, @lpMem, @nInjectCodeSize, MEM_RELEASE
;    mov @lpMem, NULL
;  .endif

  .if @hProcess
    ;调用 CloseHandle api函数,关闭进程句柄
    invoke CloseHandle, @hProcess
    mov @hProcess, NULL
  .endif
  ret
Inject endp

DialogProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
  local @szUsername[256]:BYTE
  local @szPassword[256]:BYTE

  .if uMsg == WM_INITDIALOG

    invoke SetDlgItemText, hWnd, EDT_USERNAME, 
      addr g_szUsername
    invoke SetDlgItemText, hWnd, EDT_PASSWORD, 
      addr g_szPassword
      
    mov eax, TRUE
    ret
  .elseif uMsg == WM_COMMAND
    mov eax, wParam
    .if ax == CMD_CHECK
      invoke GetDlgItemText, hWnd, EDT_USERNAME, 
        addr @szUsername, sizeof @szUsername
      invoke GetDlgItemText, hWnd, EDT_PASSWORD, 
        addr @szPassword, sizeof @szPassword

      invoke MessageBox, NULL, addr @szUsername, addr @szPassword, MB_OK
      
      mov eax, TRUE
      ret
    .elseif ax == CMD_CANCEL
      invoke SendMessage, hWnd, WM_CLOSE, 0, 0
      
      mov eax, TRUE
      ret
    .endif

  .elseif uMsg == WM_CLOSE
      invoke EndDialog, hWnd, 0
  .endif

  mov eax, FALSE
  ret
DialogProc endp

WndProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
  local @ps:PAINTSTRUCT
	local @hdc:HDC
  local @rt:RECT

  .if uMsg == WM_LBUTTONDOWN
    invoke Inject    ;鼠标左键,调用我们写的注入函数

  .elseif uMsg == WM_COMMAND
    mov eax, wParam
    .if ax == IDM_FILE_EXIT
      invoke SendMessage, hWnd, WM_DESTROY, 0, 0

    .elseif ax == IDM_FILE_OPEN
      invoke MessageBox, NULL, offset g_szHello, 
        offset g_szTitle, MB_OK

    .elseif ax == IDM_HELP_ABOUT
      invoke DialogBoxParam, g_hInst, DLG_ABOUT, 
        hWnd, offset DialogProc, NULL

    .endif

  .elseif uMsg == WM_PAINT
    invoke BeginPaint, hWnd, addr @ps
    mov @hdc, eax
    invoke GetClientRect, hWnd, addr @rt
    invoke DrawText, @hdc, offset g_szHello, sizeof g_szHello - 1,
      addr @rt, DT_CENTER or DT_VCENTER or DT_SINGLELINE
    invoke EndPaint, hWnd, addr @ps

  .elseif uMsg == WM_DESTROY
    invoke PostQuitMessage, 0

  .else
    invoke DefWindowProc, hWnd, uMsg, wParam, lParam
    ret
  .endif

  xor eax, eax
  ret
WndProc endp

InitInstance proc hInst:HANDLE
  local @hWnd:HWND
  invoke CreateWindowEx, NULL, offset g_szHello, offset g_szTitle, 
    WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, 
    NULL, NULL, hInst, NULL
  mov @hWnd, eax

  .if !@hWnd
    mov eax, FALSE
    ret
  .endif

  invoke ShowWindow, @hWnd, SW_SHOW
  invoke UpdateWindow, @hWnd

  mov eax, TRUE
  ret
InitInstance endp

MyRegisterClass proc hInst:HANDLE
  local @wcex:WNDCLASSEX

  invoke RtlZeroMemory, addr @wcex, sizeof @wcex
	mov @wcex.cbSize, sizeof WNDCLASSEX
	mov @wcex.style, CS_HREDRAW or CS_VREDRAW;
	mov @wcex.lpfnWndProc, offset WndProc
  push hInst
	pop @wcex.hInstance
	mov @wcex.hbrBackground, COLOR_WINDOW+1
	mov @wcex.lpszClassName, offset g_szHello;

  invoke LoadIcon, hInst, IDI_HELLO
  mov @wcex.hIcon, eax
	mov @wcex.lpszMenuName, IDM_TESTSDK
  invoke LoadIcon, hInst, IDI_HELLO
  mov @wcex.hIconSm, eax

  invoke RegisterClassEx, addr @wcex
  ret
MyRegisterClass endp

WinMain proc hInst:HANDLE
  local @msg:MSG

  invoke MyRegisterClass, hInst

  invoke InitInstance, hInst
  .if !eax
    mov eax, FALSE
    ret
  .endif

  invoke GetMessage, addr @msg, NULL, 0, 0
  .while eax
    invoke DispatchMessage, addr @msg
    invoke GetMessage, addr @msg, NULL, 0, 0
  .endw

  mov eax, @msg.wParam
  ret
WinMain endp

START:
  invoke GetModuleHandle, NULL
  mov g_hInst, eax
  invoke WinMain, eax
  invoke ExitProcess, 0

end START
