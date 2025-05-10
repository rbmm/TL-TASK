sc create kilk binpath= "%~dp0\kilk.dll" type= kernel start= demand error= normal
copy LdrpKernel32.dll %systemroot%\system32\LdrpKernel32.dll
copy wow\LdrpKernel32.dll %systemroot%\syswow64\LdrpKernel32.dll