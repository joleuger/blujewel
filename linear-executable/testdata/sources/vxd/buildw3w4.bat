@echo off
rem Builds the four devlib archives committed in ../../fixtures/ from the two
rem drivers built by build.bat (hello.vxd, hello2.vxd). Copy the results over
rem singlew3.BIN / singlew4.BIN / doublew3.BIN / doublew4.BIN.
rem
rem These command lines are reconstructed from the committed archives (their
rem names and shapes) — devlib is a DDK tool, so they were run on Windows, not
rem on the Linux development box.
rem
rem devlib names the first member slot after the output file and keeps the
rem module name for later slots, hence SINGLEW3 / DOUBLEW3 + HELLO2.
devlib -a singlew3.vxd hello.vxd
devlib -a singlew4.vxd hello.vxd
devlib -p singlew4.vxd
devlib -a doublew3.vxd hello.vxd hello2.vxd
devlib -a doublew4.vxd hello.vxd hello2.vxd
devlib -p doublew4.vxd
