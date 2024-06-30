STATE_READY		EQU	00h
STATE_SINGLESTEP	EQU	01h
STATE_BREAK		EQU	02h
STATE_BREAKALT		EQU	03h
STATE_BREAKMEM		EQU	04h

STATE_HANDLED		EQU	10h
STATE_UNHANDLED		EQU	11h

STATE_BUSY		EQU	20h

KTRAP_SIZE		EQU	168h

DATA_STATE	STRUCT	1
	State		DD	?
	ThreadID	DD	?

	RegCr2		DQ	?
	RegDr0		DQ	?
	RegDr1		DQ	?
	RegDr2		DQ	?
	RegDr3		DQ	?
	RegDr6		DQ	?
	RegDr7		DQ	?

	RegIp		DQ	?
	RegCS		DQ	?
	RegFlags	DQ	?
	RegSp		DQ	?

	RegDi		DQ	?
	RegSi		DQ	?
	RegBp		DQ	?
	RegBx		DQ	?
	RegDx		DQ	?
	RegCx		DQ	?
	RegAx		DQ	?

	Reg8		DQ	?
	Reg9		DQ	?
	Reg10		DQ	?
	Reg11		DQ	?
	Reg12		DQ	?
	Reg13		DQ	?
	Reg14		DQ	?
	Reg15		DQ	?
DATA_STATE	ENDS