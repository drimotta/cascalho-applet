/* The dialogs on Linux (GNOME), with GTK 4. Each call runs its own loop
 * until the user answers, so the agent stays single-threaded. */
#include "ui.h"

#include <gtk/gtk.h>
#include <string.h>

typedef struct {
    int done;
    int result;
} answer;

static int ready(void) {
    static int inited = 0;
    if (!inited) inited = gtk_init_check() ? 1 : -1;
    return inited == 1;
}

static void finish(answer *a, int result) {
    a->result = result;
    a->done = 1;
}

static gboolean on_close(GtkWindow *w, gpointer data) {
    (void)w;
    finish(data, 0);
    return TRUE;
}

static void on_yes(GtkButton *b, gpointer data) {
    (void)b;
    finish(data, 1);
}

static void on_no(GtkButton *b, gpointer data) {
    (void)b;
    finish(data, 0);
}

static GtkWidget *window_for(const char *title, answer *a) {
    GtkWidget *w = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(w), title);
    gtk_window_set_modal(GTK_WINDOW(w), TRUE);
    gtk_window_set_resizable(GTK_WINDOW(w), FALSE);
    gtk_window_set_default_size(GTK_WINDOW(w), 440, -1);
    g_signal_connect(w, "close-request", G_CALLBACK(on_close), a);
    return w;
}

static GtkWidget *column(GtkWidget *window, const char *detail) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(box, 18);
    gtk_widget_set_margin_bottom(box, 18);
    gtk_widget_set_margin_start(box, 18);
    gtk_widget_set_margin_end(box, 18);
    GtkWidget *label = gtk_label_new(detail);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0);
    gtk_label_set_max_width_chars(GTK_LABEL(label), 60);
    gtk_box_append(GTK_BOX(box), label);
    gtk_window_set_child(GTK_WINDOW(window), box);
    return box;
}

static GtkWidget *buttons(GtkWidget *box, const char *yes, answer *a, GtkWidget **yes_button) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(row, GTK_ALIGN_END);
    GtkWidget *no = gtk_button_new_with_label("Cancel");
    GtkWidget *ok = gtk_button_new_with_label(yes);
    gtk_widget_add_css_class(ok, "suggested-action");
    g_signal_connect(no, "clicked", G_CALLBACK(on_no), a);
    g_signal_connect(ok, "clicked", G_CALLBACK(on_yes), a);
    gtk_box_append(GTK_BOX(row), no);
    gtk_box_append(GTK_BOX(row), ok);
    gtk_box_append(GTK_BOX(box), row);
    if (yes_button) *yes_button = ok;
    return row;
}

static void run(GtkWidget *w, answer *a) {
    gtk_window_present(GTK_WINDOW(w));
    while (!a->done) g_main_context_iteration(NULL, TRUE);
    gtk_window_destroy(GTK_WINDOW(w));
    while (g_main_context_pending(NULL)) g_main_context_iteration(NULL, FALSE);
}

int ui_confirm(const char *title, const char *detail) {
    if (!ready()) return 0;
    answer a = {0, 0};
    GtkWidget *w = window_for(title, &a);
    GtkWidget *box = column(w, detail);
    buttons(box, "Allow", &a, NULL);
    run(w, &a);
    return a.result;
}

static void on_activate(GtkPasswordEntry *e, gpointer data) {
    (void)e;
    finish(data, 1);
}

int ui_pick_certificate(const char *title, const char *detail, const ui_cert *certs, size_t count,
                        size_t *chosen, char *pin, size_t pin_size) {
    if (!ready() || count == 0) return 0;
    answer a = {0, 0};
    GtkWidget *w = window_for(title, &a);
    GtkWidget *box = column(w, detail);

    GtkStringList *items = gtk_string_list_new(NULL);
    for (size_t i = 0; i < count; i++) {
        char line[512];
        snprintf(line, sizeof line, "%s  (until %.10s, %s)", certs[i].subject ? certs[i].subject : "?",
                 certs[i].not_after ? certs[i].not_after : "?", certs[i].token ? certs[i].token : "?");
        gtk_string_list_append(items, line);
    }
    GtkWidget *drop = gtk_drop_down_new(G_LIST_MODEL(items), NULL);
    gtk_box_append(GTK_BOX(box), drop);

    GtkWidget *entry = gtk_password_entry_new();
    gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(entry), FALSE);
    g_object_set(entry, "placeholder-text", "PIN", NULL);
    g_signal_connect(entry, "activate", G_CALLBACK(on_activate), &a);
    gtk_box_append(GTK_BOX(box), entry);
    buttons(box, "Sign", &a, NULL);
    gtk_widget_grab_focus(entry);

    run_loop:
    gtk_window_present(GTK_WINDOW(w));
    while (!a.done) g_main_context_iteration(NULL, TRUE);
    const char *typed = gtk_editable_get_text(GTK_EDITABLE(entry));
    if (a.result && (!typed || !*typed)) { /* OK with no PIN: ask again */
        a.done = 0;
        goto run_loop;
    }
    int ok = a.result && strlen(typed) < pin_size;
    if (ok) {
        memcpy(pin, typed, strlen(typed) + 1);
        *chosen = gtk_drop_down_get_selected(GTK_DROP_DOWN(drop));
    }
    gtk_editable_set_text(GTK_EDITABLE(entry), "");
    gtk_window_destroy(GTK_WINDOW(w));
    while (g_main_context_pending(NULL)) g_main_context_iteration(NULL, FALSE);
    return ok && *chosen < count;
}
