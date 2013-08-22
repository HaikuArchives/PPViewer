/*
 
MainWindow.h

PP Viewer -- decrypts PowerPacker encrypted files using Stuart Caie's ppcrack 0.1
decrypting routines. Please see his web site at http://www.kyz.uklinux.net/ for
updated version of ppcrack.

Copyright (C) 2002 Maurice Michalski, http://fetal.de, http://maurice-michalski.de

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be included in all copies
or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
*/

#ifndef _MAINWINDOW_H_
#define _MAINWINDOW_H_

#include <Window.h>
#include <View.h>
#include <TextView.h>
#include <MenuBar.h>
#include <Menu.h>
#include <MenuItem.h>
#include <ScrollView.h>
#include <File.h>

class MainWindow : public BWindow {
public:
	MainWindow(BRect frame, const char *title, BFile *file);
	MainWindow(BRect frame, const char *title, const char *text, off_t length);
	~MainWindow();
	
	virtual bool QuitRequested();
	virtual void FrameResized(float width, float height);
	virtual void MessageReceived(BMessage *msg);
	BTextView	*contentView;
	
private:
	BScrollView	*scrollView;
	BMenu		*mainM,
			*documentM,
			*alignM;
	BMenuItem	*openMI,
			*saveMI,
			*aboutMI,
			*exitMI,
			*leftalignMI,
			*centeralignMI,
			*rightalignMI,
			*wordwrapMI;
	float		menu_height;
};

#endif