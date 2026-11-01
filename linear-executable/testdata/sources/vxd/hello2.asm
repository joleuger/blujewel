;==============================================================================
; HELLO.ASM - Assembler-Teil des dynamisch ladbaren VxD "HELLO"
;
; Enthaelt: DDB, Control-Procedure und die Sprungstellen in den C-Code
; (helloc.c). Zu assemblieren mit ML.EXE (MASM 6.11d aus dem DDK).
;==============================================================================

        .386p

        include vmm.inc

; C-Funktionen (cdecl, Namen mit fuehrendem Unterstrich)
EXTRN   _Hello2Init:NEAR
EXTRN   _Hello2Exit:NEAR
EXTRN   _Hello2Dioc:NEAR

;------------------------------------------------------------------------------
; Device Descriptor Block (wird als HELLO_DDB exportiert, siehe hello.def)
;------------------------------------------------------------------------------
Declare_Virtual_Device HELLO2, 1, 0, HELLO2_Control, Undefined_Device_ID, Undefined_Init_Order

VxD_LOCKED_CODE_SEG

;------------------------------------------------------------------------------
; Control Procedure: der VMM ruft sie mit der Nachricht in EAX auf.
; Control_Dispatch springt zum Handler, der dann selbst mit RET zurueckkehrt.
;------------------------------------------------------------------------------
BeginProc HELLO2_Control

        Control_Dispatch Sys_Dynamic_Device_Init, HELLO2_OnLoad
        Control_Dispatch Sys_Dynamic_Device_Exit, HELLO2_OnUnload
        Control_Dispatch W32_DEVICEIOCONTROL,     HELLO2_OnDioc

        clc                             ; alle anderen Nachrichten: ok
        ret

EndProc HELLO2_Control

;------------------------------------------------------------------------------
; Sys_Dynamic_Device_Init: VxD wurde geladen. Carry gesetzt = Laden abbrechen.
;------------------------------------------------------------------------------
BeginProc HELLO2_OnLoad

        ;Trace_Out "HELLO2.VXD: loaded"
        call    _Hello2Init
        clc
        ret

EndProc HELLO2_OnLoad

;------------------------------------------------------------------------------
; Sys_Dynamic_Device_Exit: VxD wird entladen. Carry gesetzt = Entladen verweigern.
;------------------------------------------------------------------------------
BeginProc HELLO2_OnUnload

        call    _Hello2Exit
        ;Trace_Out "HELLO2.VXD: entladen"
        clc
        ret

EndProc HELLO2_OnUnload

;------------------------------------------------------------------------------
; W32_DEVICEIOCONTROL: ESI = Zeiger auf DIOCPARAMETERS.
; Rueckgabe in EAX: 0 = Erfolg, sonst Win32-Fehlercode. Kein Carry-Flag.
;------------------------------------------------------------------------------
BeginProc HELLO2_OnDioc

        push    esi                     ; Argument fuer C (cdecl)
        call    _Hello2Dioc
        add     esp, 4
        ret

EndProc HELLO2_OnDioc

VxD_LOCKED_CODE_ENDS

        END
