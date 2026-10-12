//go:build darwin

// Package clipboard watches and writes the macOS pasteboard (NSPasteboard)
// using the general pasteboard change count, mirroring what WeType's
// ClipboardMonitor does (see report §3.1).
package clipboard

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit -framework Foundation

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

static NSInteger lastChangeCount = -2; // force initial read

// Returns YES if the pasteboard changed since the last poll. Text is copied
// when present; otherwise PNG/TIFF bytes are copied when present.
BOOL clip_poll_darwin(char **outText, void **outData, int *dataLen) {
    @autoreleasepool {
        NSPasteboard *pb = [NSPasteboard generalPasteboard];
        NSInteger cc = [pb changeCount];
        if (cc == lastChangeCount) return NO;
        lastChangeCount = cc;

        NSString *text = nil;
        if ([pb.types containsObject:NSPasteboardTypeString]) {
            text = [pb stringForType:NSPasteboardTypeString];
        }
        NSData *png = nil;
        if ([pb.types containsObject:NSPasteboardTypePNG]) {
            png = [pb dataForType:NSPasteboardTypePNG];
        } else if ([pb.types containsObject:NSPasteboardTypeTIFF]) {
            NSData *tiff = [pb dataForType:NSPasteboardTypeTIFF];
            NSImage *img = [[NSImage alloc] initWithData:tiff];
            if (img) {
                // convert TIFF -> PNG so the wire format is uniform
                CGImageRef cg = [img CGImageForProposedRect:nil context:nil hints:nil];
                NSBitmapImageRep *rep = [[NSBitmapImageRep alloc] initWithCGImage:cg];
                png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
            }
        }
        if (text) {
            *outText = strdup(text.UTF8String);
            if (png) {
                *outData = malloc(png.length);
                memcpy(*outData, png.bytes, png.length);
                *dataLen = (int)png.length;
            }
            return YES;
        }
        if (png) {
            *outData = malloc(png.length);
            memcpy(*outData, png.bytes, png.length);
            *dataLen = (int)png.length;
            return YES;
        }
        return NO;
    }
}

BOOL clip_write_text_darwin(const char *text) {
    @autoreleasepool {
        NSPasteboard *pb = [NSPasteboard generalPasteboard];
        [pb clearContents];
        NSString *s = [NSString stringWithUTF8String:text];
        BOOL ok = [pb setString:s forType:NSPasteboardTypeString];
        if (ok) lastChangeCount = [pb changeCount]; // don't echo our own write
        return ok;
    }
}

// Writes PNG bytes as image on the pasteboard.
BOOL clip_write_image_darwin(const void *pngData, int len) {
    @autoreleasepool {
        NSData *png = [NSData dataWithBytes:pngData length:len];
        NSImage *img = [[NSImage alloc] initWithData:png];
        if (!img) return NO;
        NSPasteboard *pb = [NSPasteboard generalPasteboard];
        [pb clearContents];
        NSArray *types = @[NSPasteboardTypePNG, NSPasteboardTypeTIFF];
        [pb declareTypes:types owner:nil];
        BOOL ok = [pb setData:png forType:NSPasteboardTypePNG];
        if (ok) lastChangeCount = [pb changeCount];
        return ok;
    }
}
*/
import "C"
import (
	"unsafe"
)

// Update is one observed clipboard change.
type Update struct {
	Text    string
	PNGData []byte // non-nil when the change carried an image
}

// Poll returns the new clipboard contents if changeCount moved, else ok=false.
func Poll() (Update, bool) {
	var text *C.char
	var data unsafe.Pointer
	var dlen C.int
	ok := C.clip_poll_darwin(&text, &data, &dlen)
	if !ok {
		return Update{}, false
	}
	u := Update{}
	if text != nil {
		u.Text = C.GoString(text)
		C.free(unsafe.Pointer(text))
	}
	if data != nil && dlen > 0 {
		u.PNGData = C.GoBytes(data, dlen)
		C.free(data)
	}
	return u, true
}

// WriteText replaces the pasteboard text.
func WriteText(s string) bool {
	ctext := C.CString(s)
	defer C.free(unsafe.Pointer(ctext))
	return bool(C.clip_write_text_darwin(ctext))
}

// WriteImage writes PNG bytes as the pasteboard image.
func WriteImage(png []byte) bool {
	if len(png) == 0 {
		return false
	}
	return bool(C.clip_write_image_darwin(unsafe.Pointer(&png[0]), C.int(len(png))))
}
