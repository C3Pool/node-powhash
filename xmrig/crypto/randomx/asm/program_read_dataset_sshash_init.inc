	sub rsp, 200
	mov qword ptr [rsp+64], rbx
	mov qword ptr [rsp+56], r8
	mov qword ptr [rsp+48], r9
	mov qword ptr [rsp+40], r10
	mov qword ptr [rsp+32], r11
	mov qword ptr [rsp+24], r12
	mov qword ptr [rsp+16], r13
	mov qword ptr [rsp+8], r14
	mov qword ptr [rsp+0], r15
	;# C3Pool fix: restore v29.0.6 order (upstream 29.2.6 swapped ror/xor and
	;# changed block-number extraction -> computed item from "mx" not "ma" ->
	;# light-mode JIT gave 100% wrong hashes; full-dataset mining never runs this
	;# stub so it went unnoticed). Now matches program_read_dataset.inc.
	xor rbp, rax                       ;# modify "mx"
	ror rbp, 32                        ;# swap "ma" and "mx"
	mov ebx, ebp                       ;# ebx = ma
	and ebx, RANDOMX_DATASET_BASE_MASK
	shr ebx, 6                         ;# ebx = Dataset block number
	;# add ebx, datasetOffset / 64
	;# call 32768