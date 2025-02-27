# TL-TASK

run "ins tl-drv.bat" for install driver

run "ins tl-srv.bat" for install and start service

"RbmmTL" ( display name "Rbmm TL Service" ) accept start/pause/continue/stop

for uninstall, do in reverse order:

run "del tl-srv.bat"

run "del tl-drv.bat"

logs from service will be in \systemroot\temp\TL-SRV\ folder ( usually c:\windows\temp\TL-SRV\ )

log from driver in debugview.exe

Platform: Windows 7/8/8.1/10/11 (x64)
