sc create iapc binpath= "%~dp0\inj-drv.dll" type= kernel start= demand error= normal
copy inj-dll.dll %systemroot%\system32\]]rbmm[[.dll
copy wow\inj-dll.dll %systemroot%\syswow64\]]rbmm[[.dll