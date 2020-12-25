FSOUND_OUTPUTBUFF_END		EQU	0
FSOUND_MIXDIR_FORWARDS		EQU	1
FSOUND_SAMPLEBUFF_END		EQU	1
FSOUND_MIXDIR_BACKWARDS		EQU	2
FSOUND_LOOP_NORMAL		EQU	2
FSOUND_LOOP_BIDI		EQU	4

FSOUND_SAMPLE	STRUCT	8
	buff			DQ	?

	blength			DD	?
	loopstart		DD	?
	looplen			DD	?
	defvol			DB	?
	finetune		DB	?

	deffreq			DD	?
	defpan			DD	?

	bits			DB	?
	loopmode		DB	?

	globalvol		DB	?
	relative		DB	?
	middlec			DD	?
	susloopbegin		DD	?
	susloopend		DD	?
	vibspeed		DB	?
	vibdepth		DB	?
	vibtype			DB	?
	vibrate			DB	?
FSOUND_SAMPLE	ENDS

FSOUND_CHANNEL	STRUCT	8
	index			DD	?
	volume			DD	?
	frequency		DD	?
	pan			DD	?
	actualvolume		DD	?
	actualpan		DD	?
	sampleoffset		DD	?

	sptr			DQ	?

	leftvolume		DD	?
	rightvolume		DD	?
	mixpos			DD	?
	mixposlo		DD	?
	speedlo			DD	?
	speedhi			DD	?
	speeddir		DD	?

	ramp_lefttarget		DD	?
	ramp_righttarget	DD	?
	ramp_leftvolume		DD	?
	ramp_rightvolume	DD	?
	ramp_leftspeed		DD	?
	ramp_rightspeed		DD	?
	ramp_count		DD	?
FSOUND_CHANNEL	ENDS