# coding = 'utf-8'

from ctypes import *

try:
    from winnt import *
    from win_cbasictypes import *
except ImportError:
    from .winnt import *
    from .win_cbasictypes import *

class tagRECT(Structure):
    _fields_ = [('left', LONG), 
                ('top', LONG),
                ('right', LONG),
                ('bottom', LONG)
    ]

RECT = tagRECT
PRECT = POINTER(tagRECT)
NPRECT = PRECT
LPRECT = PRECT

RECTL = tagRECT
PRECTL = PRECT
LPRECTL = PRECT

class tagPOINT(Structure):
    _fields_ = [("x", LONG),
                ("y", LONG)]
    
POINT = tagPOINT
PPOINT = POINTER(POINT)
NPPOINT = PPOINT
LPPOINT = PPOINT

POINTL = tagPOINT
PPOINTL = PPOINT

class tagSIZE(Structure):
    _fields_ = [('cx', LONG),
                ('cy', LONG)
    ]

SIZE = tagSIZE
PSIZE = POINTER(SIZE)
LPSIZE = PSIZE

SIZEL = SIZE
PSIZEL = PSIZE
LPSIZEL = PSIZE

class tagPOINTS(Structure):
    _fields_ = [('x', SHORT),
                ('y', SHORT)
    ]

POINTS = tagPOINTS
PPOINTS = POINTER(POINTS)
LPPOINTS = PPOINTS

APP_LOCAL_DEVICE_ID_SIZE = 32

class APP_LOCAL_DEVICE_ID(Structure):
    _fields_ = [('value', BYTE * APP_LOCAL_DEVICE_ID_SIZE)]

DM_UPDATE = 1
DM_COPY = 2
DM_PROMPT = 4
DM_MODIFY = 8

DM_IN_BUFFER = DM_MODIFY
DM_IN_PROMPT = DM_PROMPT
DM_OUT_BUFFER = DM_COPY
DM_OUT_DEFAULT = DM_UPDATE

DC_FIELDS = 1
DC_PAPERS = 2
DC_PAPERSIZE = 3
DC_MINEXTENT = 4
DC_MAXEXTENT = 5
DC_BINS = 6
DC_DUPLEX = 7
DC_SIZE = 8
DC_EXTRA = 9
DC_VERSION = 10
DC_DRIVER = 11
DC_BINNAMES = 12
DC_ENUMRESOLUTIONS = 13
DC_FILEDEPENDENCIES = 14
DC_TRUETYPE = 15
DC_PAPERNAMES = 16
DC_ORIENTATION = 17
DC_COPIES = 18
