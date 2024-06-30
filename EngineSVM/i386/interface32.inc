STATE_READY		EQU	00h
STATE_SINGLESTEP	EQU	01h
STATE_BREAK		EQU	02h
STATE_BREAKMEM		EQU	03h
STATE_BREAKCPUID	EQU	04h

STATE_HANDLED		EQU	10h
STATE_UNHANDLED		EQU	11h

STATE_BUSY		EQU	20h

KTRAP_SIZE		EQU	29ch

VMCB_RSP_OFFSET		EQU	400h+1d8h
VMCB_RIP_OFFSET		EQU	400h+178h

DATA_STATE	STRUCT	1
	State		DD	?
	ThreadID	DD	?

	RegCr2		DD	?
	RegDr0		DD	?
	RegDr1		DD	?
	RegDr2		DD	?
	RegDr3		DD	?
	RegDr6		DD	?
	RegDr7		DD	?

	RegIp		DD	?
	RegCS		DD	?
	RegFlags	DD	?
	RegSp		DD	?

	RegDi		DD	?
	RegSi		DD	?
	RegBp		DD	?
	RegSp0		DD	?
	RegBx		DD	?
	RegDx		DD	?
	RegCx		DD	?
	RegAx		DD	?
DATA_STATE	ENDS