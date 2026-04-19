.code

ALIGN 1
public	GenTbl
GenTbl:
	dq	0	;; SystemTable
	dq	0	;; FreePages

public GetRip

GetRip proc
	pop	rax
	sub	rax, 5
	ret
GetRip endp

public GetPtr

GetPtr proc
	call	get_ret_ptr
get_ret_ptr:
	pop	rax
	sub	rax, 5
	ret
GetPtr endp

public ExitLb
ExitLb:
    db 'ENDOFCODE'

END