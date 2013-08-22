/*
 
AboutWindow.cpp

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

#include "AboutWindow.h"
#include <GraphicsDefs.h>


AboutView::AboutView(BRect frame, const char *name, BBitmap *icon)
		: BView(frame, name, B_FOLLOW_ALL, B_WILL_DRAW) {	
	SetViewColor(216,216,216);
	bIcon=new BBitmap(BRect(0,0,31,31), B_CMAP8);
}


AboutView::~AboutView() {
}


void AboutView::SetIcon(BBitmap *icon) {
	bIcon->SetBits(icon->Bits(), icon->BitsLength(), 0, icon->ColorSpace());
	Invalidate();
}


void AboutView::Draw(BRect updateRect) {
	if (BRect(0,0,21+33,Bounds().Height()).Intersects(updateRect)) {
		SetDrawingMode(B_OP_OVER);
		SetHighColor(184,184,184,255);
		FillRect(BRect(0,0,10+23,Bounds().Height()));
		SetHighColor(0,0,0,255);
		DrawBitmap(bIcon, BPoint(21,10));
	}
}


AboutWindow::AboutWindow(BRect frame, const char *title)
		: BWindow(frame, title, B_FLOATING_WINDOW_LOOK, B_MODAL_APP_WINDOW_FEEL, B_NOT_ZOOMABLE | B_NOT_RESIZABLE) {
	vAbout=new AboutView(Bounds(), "AboutView", NULL);	
	AddChild(vAbout);
	
	applicationNameSV=new BStringView(BRect(60,1, frame.Width()-60, 27), "applicationNameSV", "");
	applicationNameSV->SetFont(be_bold_font);
	vAbout->AddChild(applicationNameSV);

	versionNumberSV=new BStringView(BRect(applicationNameSV->StringWidth(applicationNameSV->Text())+65, 1, frame.Width()-5, 27), "versionNumberSV", "");
	versionNumberSV->SetFontSize(10);
	vAbout->AddChild(versionNumberSV);

	copyrightStringSV=new BStringView(BRect(60,27, frame.Width()-60, 41), "copyrightStringSV", "");
	copyrightStringSV->SetFontSize(10);
	vAbout->AddChild(copyrightStringSV);

	textTV=new BTextView(BRect(60,55, frame.right-10, frame.bottom-8), "textTV", BRect(1,1,frame.Width()-72,400), B_FOLLOW_LEFT | B_FOLLOW_TOP, B_WILL_DRAW);
	textTV->SetViewColor(216,216,216,255);
	textTV->MakeEditable(false);
	textTV->MakeSelectable(false);
	textTV->SetWordWrap(true);
	BFont	*font=new BFont(be_plain_font);
	font->SetSize(10);
	textTV->SetFontAndColor(font);
	vAbout->AddChild(textTV);
	delete font;
}


AboutWindow::~AboutWindow() {
}


void AboutWindow::SetApplicationName(const char *name) {
	font_height	boldheight, plainheight;
	
	applicationNameSV->GetFontHeight(&boldheight);
	versionNumberSV->GetFontHeight(&plainheight);
	
	applicationNameSV->SetText(name);
	versionNumberSV->ResizeTo((Bounds().Width()-5)-(applicationNameSV->StringWidth(applicationNameSV->Text())+65), 26);
	versionNumberSV->MoveTo(applicationNameSV->StringWidth(applicationNameSV->Text())+65, applicationNameSV->Frame().top-(boldheight.descent-plainheight.descent));
}


void AboutWindow::SetVersionNumber(const char *version) {
	versionNumberSV->SetText(version);
}


void AboutWindow::SetIcon(BBitmap *icon) {
	vAbout->SetIcon(icon);
}


void AboutWindow::SetCopyrightString(const char *copyright) {
	copyrightStringSV->SetText(copyright);
}


void AboutWindow::SetText(const char *text) {
	textTV->SetText(text);
}


bool AboutWindow::QuitRequested() {
	Quit();
	return false;
}


