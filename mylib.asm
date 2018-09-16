.386
.model flat, stdcall
option casemap:none

include windows.inc
include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib

.data

.code
ShowMsg proc C szText:LPSTR, szTitle:LPSTR

  invoke MessageBox, NULL, szText, szTitle, MB_OK
  ret

ShowMsg endp

end