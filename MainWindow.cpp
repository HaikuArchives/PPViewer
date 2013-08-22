/*
 
MainWindow.cpp

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

#include "MainWindow.h"
#include <Application.h>
#include "app.h"

#define PP_ALIGNCHANGED	'PPal'
#define PP_WORDWRAP		'PPww'

MainWindow::MainWindow(BRect frame, const char *title, BFile *file)
		: BWindow(frame, title, B_DOCUMENT_WINDOW_LOOK, B_NORMAL_WINDOW_FEEL, 0) {
		
	off_t filesize;
	file->GetSize(&filesize);
	
	BMenuBar *mb=new BMenuBar(BRect(0,0,frame.Width(),10), "MenuBar");
	mainM=new BMenu("File");
	documentM=new BMenu("Document");
	alignM=new BMenu("Align");
	alignM->SetRadioMode(true);
	
	BMessage	*savemsg=new BMessage(PP_SAVE_FILE);
	savemsg->AddPointer("source",this);
	
	openMI=new BMenuItem("Open"B_UTF8_ELLIPSIS, new BMessage(PP_OPEN_FILE), 'O');
	saveMI=new BMenuItem("Save"B_UTF8_ELLIPSIS, savemsg, 'S');
	aboutMI=new BMenuItem("About"B_UTF8_ELLIPSIS, new BMessage(B_ABOUT_REQUESTED));
	exitMI=new BMenuItem("Quit", new BMessage(B_QUIT_REQUESTED), 'Q');

	leftalignMI=new BMenuItem("Left", new BMessage(PP_ALIGNCHANGED));
	rightalignMI=new BMenuItem("Right", new BMessage(PP_ALIGNCHANGED));
	centeralignMI=new BMenuItem("Center", new BMessage(PP_ALIGNCHANGED));
	wordwrapMI=new BMenuItem("Wrap Lines", new BMessage(PP_WORDWRAP));
	leftalignMI->SetMarked(true);
	
	BRect	rect=Bounds();
	rect.bottom-=B_H_SCROLL_BAR_HEIGHT;
	rect.right-=B_V_SCROLL_BAR_WIDTH;
	BRect	text_rect=rect;
	text_rect.InsetBy(3,3);

	contentView=new BTextView(rect, "contentView", text_rect,be_fixed_font, &((rgb_color){0,0,0,255}),B_FOLLOW_ALL_SIDES, B_WILL_DRAW);
	scrollView=new BScrollView("scrollView", contentView, B_FOLLOW_ALL_SIDES, 0, true, true);
	contentView->MakeEditable(true);
	contentView->MakeResizable(false, scrollView);
	contentView->SetStylable(false);
	AddChild(scrollView);
	AddChild(mb);
	mb->AddItem(mainM);
	mb->AddItem(documentM);
	mainM->AddItem(openMI);
	mainM->AddItem(saveMI);
	mainM->AddSeparatorItem();
	mainM->AddItem(aboutMI);
	mainM->AddItem(exitMI);
	
	documentM->AddItem(alignM);
	alignM->AddItem(leftalignMI);
	alignM->AddItem(centeralignMI);
	alignM->AddItem(rightalignMI);
	documentM->AddItem(wordwrapMI);
	
	//MoveTo(40,40);
	float width;
	mb->GetPreferredSize(&width,&menu_height);
	scrollView->MoveBy(0,menu_height+1);
	scrollView->ResizeBy(0,-(menu_height+1));
	mainM->SetTargetForItems(be_app_messenger);
	documentM->SetTargetForItems(this);
	alignM->SetTargetForItems(this);
	contentView->SetWordWrap(true);
	wordwrapMI->SetMarked(true);
	contentView->SetText(file, 0, filesize);
	contentView->MakeFocus();
}

MainWindow::MainWindow(BRect frame, const char *title, const char *text, off_t length)
		: BWindow(frame, title, B_DOCUMENT_WINDOW_LOOK, B_NORMAL_WINDOW_FEEL, 0) {
		
	BMenuBar *mb=new BMenuBar(BRect(0,0,frame.Width(),10), "MenuBar");
	mainM=new BMenu("File");
	documentM=new BMenu("Document");
	alignM=new BMenu("Align");
	alignM->SetRadioMode(true);
	openMI=new BMenuItem("Open"B_UTF8_ELLIPSIS, new BMessage(PP_OPEN_FILE), 'O');
	saveMI=new BMenuItem("Save"B_UTF8_ELLIPSIS, new BMessage(PP_SAVE_FILE), 'S');
	aboutMI=new BMenuItem("About"B_UTF8_ELLIPSIS, new BMessage(B_ABOUT_REQUESTED));
	exitMI=new BMenuItem("Quit", new BMessage(B_QUIT_REQUESTED), 'Q');

	leftalignMI=new BMenuItem("Left", new BMessage(PP_ALIGNCHANGED));
	rightalignMI=new BMenuItem("Right", new BMessage(PP_ALIGNCHANGED));
	centeralignMI=new BMenuItem("Center", new BMessage(PP_ALIGNCHANGED));
	wordwrapMI=new BMenuItem("Wrap Lines", new BMessage(PP_WORDWRAP));
	leftalignMI->SetMarked(true);
	
	BRect	rect=Bounds();
	rect.bottom-=B_H_SCROLL_BAR_HEIGHT;
	rect.right-=B_V_SCROLL_BAR_WIDTH;
	BRect	text_rect=rect;
	text_rect.InsetBy(3,3);

	contentView=new BTextView(rect, "contentView", text_rect,be_fixed_font, &((rgb_color){0,0,0,255}),B_FOLLOW_ALL_SIDES, B_WILL_DRAW);
	scrollView=new BScrollView("scrollView", contentView, B_FOLLOW_ALL_SIDES, 0, true, true);
	contentView->MakeEditable(true);
	contentView->MakeResizable(false, scrollView);
	contentView->SetStylable(false);
	AddChild(scrollView);
	AddChild(mb);
	mb->AddItem(mainM);
	mb->AddItem(documentM);
	mainM->AddItem(openMI);
	mainM->AddItem(saveMI);
	mainM->AddSeparatorItem();
	mainM->AddItem(aboutMI);
	mainM->AddItem(exitMI);
	
	documentM->AddItem(alignM);
	alignM->AddItem(leftalignMI);
	alignM->AddItem(centeralignMI);
	alignM->AddItem(rightalignMI);
	documentM->AddItem(wordwrapMI);
	
	//MoveTo(40,40);
	float width;
	mb->GetPreferredSize(&width,&menu_height);
	scrollView->MoveBy(0,menu_height+1);
	scrollView->ResizeBy(0,-(menu_height+1));
	mainM->SetTargetForItems(be_app_messenger);
	documentM->SetTargetForItems(this);
	contentView->SetWordWrap(true);
	wordwrapMI->SetMarked(true);
	contentView->SetText(text, length);
	contentView->MakeFocus();
}

MainWindow::~MainWindow() {
	be_app->PostMessage(B_QUIT_REQUESTED);
}

bool MainWindow::QuitRequested() {
	Quit();
	return false;
}

void MainWindow::FrameResized(float width, float height) {
	BRect	rect=contentView->TextRect();
	if (!contentView->DoesWordWrap())
		rect.right=1600+rect.left;
	else
		rect.Set((float)3,(float)3,(float)(width-(3+B_V_SCROLL_BAR_WIDTH)), (float)(height-(menu_height+3+B_H_SCROLL_BAR_HEIGHT)));
	contentView->SetTextRect(rect);
}

void MainWindow::MessageReceived(BMessage *msg) {
	switch(msg->what) {
		case PP_ALIGNCHANGED: {
			if (leftalignMI->IsMarked())
				contentView->SetAlignment(B_ALIGN_LEFT);
			if (rightalignMI->IsMarked())
				contentView->SetAlignment(B_ALIGN_RIGHT);
			if (centeralignMI->IsMarked())
				contentView->SetAlignment(B_ALIGN_CENTER);
			break;
		}
		
		case PP_WORDWRAP: {
			contentView->SetWordWrap(!contentView->DoesWordWrap());
			wordwrapMI->SetMarked(contentView->DoesWordWrap());

			BRect	rect=contentView->TextRect();
			if (!contentView->DoesWordWrap())
				rect.right=1600+rect.left;
			else
				rect.Set((float)3,(float)3,(float)(Bounds().Width()-(3+B_V_SCROLL_BAR_WIDTH)), (float)(Bounds().Height()-(menu_height+3+B_H_SCROLL_BAR_HEIGHT)));
			contentView->SetTextRect(rect);
			break;
		}
		
		default: {
			BWindow::MessageReceived(msg);
			break;
		}
	}
}
