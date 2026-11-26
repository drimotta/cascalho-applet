/* The dialogs on macOS: NSAlert with a certificate menu and a secure PIN
 * field. The agent runs as an accessory app (no Dock icon). */
#import <Cocoa/Cocoa.h>

#include "ui.h"

#include <string.h>

static void ready(void) {
    static BOOL inited = NO;
    if (inited) return;
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    inited = YES;
}

static NSString *text(const char *s) {
    return s ? [NSString stringWithUTF8String:s] : @"";
}

int ui_confirm(const char *title, const char *detail) {
    @autoreleasepool {
        ready();
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = text(title);
        alert.informativeText = text(detail);
        [alert addButtonWithTitle:@"Allow"];
        [alert addButtonWithTitle:@"Cancel"];
        [NSApp activateIgnoringOtherApps:YES];
        return [alert runModal] == NSAlertFirstButtonReturn;
    }
}

int ui_pick_certificate(const char *title, const char *detail, const ui_cert *certs, size_t count,
                        size_t *chosen, char *pin, size_t pin_size) {
    if (count == 0) return 0;
    @autoreleasepool {
        ready();
        NSView *view = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 420, 60)];
        NSPopUpButton *menu = [[NSPopUpButton alloc] initWithFrame:NSMakeRect(0, 32, 420, 26) pullsDown:NO];
        for (size_t i = 0; i < count; i++) {
            NSString *line = [NSString stringWithFormat:@"%@  (until %.10s, %@)", text(certs[i].subject),
                                                        certs[i].not_after ? certs[i].not_after : "?",
                                                        text(certs[i].token)];
            [menu addItemWithTitle:line];
        }
        NSSecureTextField *field = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 420, 24)];
        field.placeholderString = @"PIN";
        [view addSubview:menu];
        [view addSubview:field];

        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = text(title);
        alert.informativeText = text(detail);
        alert.accessoryView = view;
        [alert addButtonWithTitle:@"Sign"];
        [alert addButtonWithTitle:@"Cancel"];
        [alert layout];
        alert.window.initialFirstResponder = field;
        [NSApp activateIgnoringOtherApps:YES];
        if ([alert runModal] != NSAlertFirstButtonReturn) return 0;

        const char *typed = field.stringValue.UTF8String;
        size_t len = typed ? strlen(typed) : 0;
        field.stringValue = @"";
        if (len == 0 || len >= pin_size) return 0;
        memcpy(pin, typed, len + 1);
        *chosen = (size_t)menu.indexOfSelectedItem;
        return *chosen < count;
    }
}
