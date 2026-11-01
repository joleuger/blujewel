;==============================================================================
; HELLO.ASM - Assembler-Teil des dynamisch ladbaren VxD "HELLO"
;
; Enthaelt: DDB, Control-Procedure und die Sprungstellen in den C-Code
; (helloc.c). Zu assemblieren mit ML.EXE (MASM 6.11d aus dem DDK).
;==============================================================================

        .386p

        include vmm.inc

; C-Funktionen (cdecl, Namen mit fuehrendem Unterstrich)
EXTRN   _HelloInit:NEAR
EXTRN   _HelloExit:NEAR
EXTRN   _HelloDioc:NEAR

;------------------------------------------------------------------------------
; Device Descriptor Block (wird als HELLO_DDB exportiert, siehe hello.def)
;------------------------------------------------------------------------------
Declare_Virtual_Device HELLO, 1, 0, HELLO_Control, Undefined_Device_ID, Undefined_Init_Order

VxD_LOCKED_CODE_SEG

;------------------------------------------------------------------------------
; Control Procedure: der VMM ruft sie mit der Nachricht in EAX auf.
; Control_Dispatch springt zum Handler, der dann selbst mit RET zurueckkehrt.
;------------------------------------------------------------------------------
BeginProc HELLO_Control

        Control_Dispatch Sys_Dynamic_Device_Init, HELLO_OnLoad
        Control_Dispatch Sys_Dynamic_Device_Exit, HELLO_OnUnload
        Control_Dispatch W32_DEVICEIOCONTROL,     HELLO_OnDioc

        clc                             ; alle anderen Nachrichten: ok
        ret

EndProc HELLO_Control

;------------------------------------------------------------------------------
; Sys_Dynamic_Device_Init: VxD wurde geladen. Carry gesetzt = Laden abbrechen.
;------------------------------------------------------------------------------
BeginProc HELLO_OnLoad

        ;Trace_Out "HELLO.VXD: loaded"
        call    _HelloInit
        clc
        ret

EndProc HELLO_OnLoad

;------------------------------------------------------------------------------
; Sys_Dynamic_Device_Exit: VxD wird entladen. Carry gesetzt = Entladen verweigern.
;------------------------------------------------------------------------------
BeginProc HELLO_OnUnload

        call    _HelloExit
        ;Trace_Out "HELLO.VXD: entladen"
        clc
        ret

EndProc HELLO_OnUnload

;------------------------------------------------------------------------------
; W32_DEVICEIOCONTROL: ESI = Zeiger auf DIOCPARAMETERS.
; Rueckgabe in EAX: 0 = Erfolg, sonst Win32-Fehlercode. Kein Carry-Flag.
;------------------------------------------------------------------------------
BeginProc HELLO_OnDioc

        push    esi                     ; Argument fuer C (cdecl)
        call    _HelloDioc
        add     esp, 4
        ret

EndProc HELLO_OnDioc

VxD_LOCKED_CODE_ENDS

        END
