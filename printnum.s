	.intel_syntax noprefix
  .text
	.globl	_start
_start:
  mov 

	mov	eax, 0x1
	mov	edi, 0x1
	mov	rsi, offset msg
	mov	edx, 14    ; write
	syscall        

	mov	eax, 60
	xor	edi, edi
	syscall        ; exit(0)

printnum:
  ; number to print in rdi

	.section	.rodata,"a"
msg:
	.ascii	"Hello, world!\n"
