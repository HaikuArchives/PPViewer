NAME = ppviewer
TYPE = APP 
SRCS = \
	AboutWindow.cpp	\
	MainWindow.cpp	\
	app.cpp			\

RSRCS = 
LIBS = be tracker $(STDCPPLIBS)
APP_MIME_SIG = application/x-vnd.Haiku-PPViewer

## Include the Makefile-Engine
DEVEL_DIRECTORY := \
	$(shell findpaths -r "makefile_engine" B_FIND_PATH_DEVELOP_DIRECTORY)
include $(DEVEL_DIRECTORY)/etc/makefile-engine
