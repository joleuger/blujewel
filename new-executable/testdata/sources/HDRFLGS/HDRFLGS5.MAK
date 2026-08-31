# Microsoft Visual C++ generated build script - Do not modify

PROJ = HDRFLGS5
DEBUG = 0
PROGTYPE = 0
CALLER = 
ARGS = 
DLLS = 
D_RCDEFINES = -d_DEBUG
R_RCDEFINES = -dNDEBUG
ORIGIN = MSVC
ORIGIN_VER = 1.00
PROJPATH = D:\MSVC15\HDRFLGS\
USEMFC = 0
CC = cl
CPP = cl
CXX = cl
CCREATEPCHFLAG = 
CPPCREATEPCHFLAG = 
CUSEPCHFLAG = 
CPPUSEPCHFLAG = 
FIRSTC = HDRFLGS.C   
FIRSTCPP =             
RC = rc
CFLAGS_D_WEXE = /nologo /G2 /W3 /Zi /AM /Od /D "_DEBUG" /FR /GA /Fd"HDRFLGS1.PDB"
CFLAGS_R_WEXE = /nologo /W3 /AM /O1 /D "NDEBUG" /FR /GA 
LFLAGS_D_WEXE = /NOLOGO /NOD /PACKC:61440 /STACK:10240 /ALIGN:16 /ONERROR:NOEXE /CO  
LFLAGS_R_WEXE = /NOLOGO /NOD /PACKC:61440 /ALIGN:16 /ONERROR:NOEXE 
LIBS_D_WEXE = oldnames libw mlibcew commdlg.lib olecli.lib olesvr.lib shell.lib 
LIBS_R_WEXE = oldnames libw mlibcew 
RCFLAGS = /nologo
RESFLAGS = /nologo
RUNFLAGS = 
DEFFILE = HDRFLGS5.DEF
OBJS_EXT = 
LIBS_EXT = 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_WEXE)
LFLAGS = $(LFLAGS_D_WEXE)
LIBS = $(LIBS_D_WEXE)
MAPFILE = nul
RCDEFINES = $(D_RCDEFINES)
!else
CFLAGS = $(CFLAGS_R_WEXE)
LFLAGS = $(LFLAGS_R_WEXE)
LIBS = $(LIBS_R_WEXE)
MAPFILE = nul
RCDEFINES = $(R_RCDEFINES)
!endif
!if [if exist MSVC.BND del MSVC.BND]
!endif
SBRS = HDRFLGS.SBR


HDRFLGS_DEP = 

all:	$(PROJ).EXE $(PROJ).BSC

HDRFLGS.OBJ:	HDRFLGS.C $(HDRFLGS_DEP)
	$(CC) $(CFLAGS) $(CCREATEPCHFLAG) /c HDRFLGS.C


$(PROJ).EXE::	HDRFLGS.OBJ $(OBJS_EXT) $(DEFFILE)
	echo >NUL @<<$(PROJ).CRF
HDRFLGS.OBJ +
$(OBJS_EXT)
$(PROJ).EXE
$(MAPFILE)
c:\msvc\lib\+
c:\msvc\mfc\lib\+
$(LIBS)
$(DEFFILE);
<<
	link $(LFLAGS) @$(PROJ).CRF
	$(RC) $(RESFLAGS) $@


run: $(PROJ).EXE
	$(PROJ) $(RUNFLAGS)


$(PROJ).BSC: $(SBRS)
	bscmake @<<
/o$@ $(SBRS)
<<
