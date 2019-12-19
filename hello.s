	.intel_syntax noprefix
  .text
	.globl	_start
_start:
	mov	eax, 0x1
	mov	edi, 0x1
	mov	rsi, offset msg
	mov	edx, 14
	syscall
	mov	eax, 60
	xor	edi, edi
	syscall
	.section	.rodata,"a"
msg:
	.ascii	"Hello, world!\n"
