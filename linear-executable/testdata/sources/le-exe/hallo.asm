; Minimales Hello World ohne C-Runtime fuer DOS32A (LE)
.386
.model flat
.stack 1000h

.data
msg db "Hallo Welt (Assembler)!", 13, 10, '$'

.code
start:
    mov  ah, 9
    mov  edx, offset msg
    int  21h
    mov  ax, 4C00h
    int  21h
end start
