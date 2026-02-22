"""Cert Watch — TLS Certificate Monitor."""
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib, Gio, Pango
import ssl, socket, threading, json, csv, io, os, gettext, locale
from datetime import datetime, timezone

APP_ID = "io.github.yeager.CertWatch"
_ = gettext.gettext

def fetch_cert_info(domain, port=443, timeout=10):
    """Fetch TLS certificate info for a domain."""
    result = {"domain": domain, "port": port, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                result["subject"] = dict(x[0] for x in cert.get("subject", ()))
                result["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                result["not_before"] = cert.get("notBefore", "")
                result["not_after"] = cert.get("notAfter", "")
                result["serial"] = cert.get("serialNumber", "")
                sans = []
                for typ, val in cert.get("subjectAltName", ()):
                    sans.append(f"{typ}: {val}")
                result["sans"] = sans
                result["cipher_suite"] = cipher[0] if cipher else ""
                result["cipher_bits"] = cipher[2] if cipher and len(cipher) > 2 else ""
                result["protocol"] = version or ""
                # Parse expiry
                try:
                    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["days_left"] = (exp - datetime.now(timezone.utc)).days
                except Exception:
                    result["days_left"] = None
                # Check HSTS via raw HTTP
                result["hsts"] = _check_hsts(domain)
    except Exception as e:
        result["error"] = str(e)
    result["checked_at"] = datetime.now().isoformat()
    return result

def _check_hsts(domain):
    try:
        import http.client
        conn = http.client.HTTPSConnection(domain, timeout=5)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        hsts = resp.getheader("Strict-Transport-Security", "")
        conn.close()
        return hsts if hsts else "Not set"
    except Exception:
        return "Check failed"



def _settings_path():
    import os
    xdg = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    d = os.path.join(xdg, "cert-watch")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "settings.json")

def _load_settings():
    import os, json
    p = _settings_path()
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return {}

def _save_settings(s):
    import json
    with open(_settings_path(), "w") as f:
        json.dump(s, f, indent=2)

class CertRow(Gtk.ListBoxRow):
    def __init__(self, info):
        super().__init__()
        self.info = info
        self.set_margin_top(2)
        self.set_margin_bottom(2)
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)

        # Status icon
        if info.get("error"):
            icon = Gtk.Image.new_from_icon_name("dialog-error-symbolic")
            icon.add_css_class("error")
        elif info.get("days_left") is not None and info["days_left"] < 14:
            icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            icon.add_css_class("warning")
        else:
            icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
            icon.add_css_class("success")
        box.append(icon)

        # Info
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        vbox.set_hexpand(True)
        domain_label = Gtk.Label(label=info["domain"], xalign=0)
        domain_label.add_css_class("heading")
        vbox.append(domain_label)

        if info.get("error"):
            sub = Gtk.Label(label=f"Error: {info['error']}", xalign=0)
            sub.add_css_class("dim-label")
            sub.set_ellipsize(Pango.EllipsizeMode.END)
        else:
            issuer = info.get("issuer", {}).get("organizationName", info.get("issuer", {}).get("commonName", "?"))
            days = info.get("days_left", "?")
            sub = Gtk.Label(label=f"Issuer: {issuer} · Expires in {days}d · {info.get('protocol', '?')}", xalign=0)
            sub.add_css_class("dim-label")
        vbox.append(sub)
        box.append(vbox)
        self.set_child(box)


class CertWatchWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Cert Watch", default_width=900, default_height=700)
        self.domains = []
        self.results = {}
        self.poll_interval = 300  # 5 min
        self.poll_source = None

        # Header bar
        header = Adw.HeaderBar()
        # Theme toggle
        self.dark_mode = False
        theme_btn = Gtk.Button(icon_name="display-brightness-symbolic", tooltip_text=_("Toggle theme"))
        theme_btn.connect("clicked", self._toggle_theme)
        header.pack_end(theme_btn)
        # Menu
        menu = Gio.Menu()
        menu.append(_("Export JSON"), "win.export-json")
        menu.append(_("Export CSV"), "win.export-csv")
        menu.append(_("About"), "win.about")
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)
        header.pack_end(menu_btn)
        # Refresh
        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text=_("Refresh all"))
        refresh_btn.connect("clicked", lambda b: self._refresh_all())
        header.pack_end(refresh_btn)

        # Actions
        for name, cb in [("export-json", self._export_json), ("export-csv", self._export_csv), ("about", self._show_about)]:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", cb)
            self.add_action(action)

        # Main layout
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        main_box.append(header)

        # Toolbar - add domain
        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        toolbar.set_margin_start(12); toolbar.set_margin_end(12)
        toolbar.set_margin_top(8); toolbar.set_margin_bottom(8)
        self.domain_entry = Gtk.Entry(placeholder_text=_("Enter domain (e.g. example.com)"), hexpand=True)
        self.domain_entry.connect("activate", self._add_domain)
        toolbar.append(self.domain_entry)
        add_btn = Gtk.Button(label=_("Add"))
        add_btn.add_css_class("suggested-action")
        add_btn.connect("clicked", self._add_domain)
        toolbar.append(add_btn)
        remove_btn = Gtk.Button(icon_name="list-remove-symbolic", tooltip_text=_("Remove selected"))
        remove_btn.connect("clicked", self._remove_selected)
        toolbar.append(remove_btn)
        main_box.append(toolbar)

        # Content - split pane
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_vexpand(True)

        # Left: domain list
        sw = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        sw.set_size_request(320, -1)
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.listbox.add_css_class("boxed-list")
        self.listbox.connect("row-selected", self._on_row_selected)
        sw.set_child(self.listbox)
        paned.set_start_child(sw)

        # Right: detail view
        detail_sw = Gtk.ScrolledWindow()
        self.detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.detail_box.set_margin_start(16); self.detail_box.set_margin_end(16)
        self.detail_box.set_margin_top(12); self.detail_box.set_margin_bottom(12)
        self.detail_label = Gtk.Label(label=_("Select a domain to view details"), xalign=0)
        self.detail_label.add_css_class("dim-label")
        self.detail_box.append(self.detail_label)
        detail_sw.set_child(self.detail_box)
        paned.set_end_child(detail_sw)
        main_box.append(paned)

        # Status bar
        self.statusbar = Gtk.Label(label=_("Ready"), xalign=0)
        self.statusbar.set_margin_start(12); self.statusbar.set_margin_end(12)
        self.statusbar.set_margin_top(4); self.statusbar.set_margin_bottom(4)
        self.statusbar.add_css_class("dim-label")
        main_box.append(self.statusbar)

        self.set_content(main_box)
        self._start_polling()

    def _set_status(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.statusbar.set_label(f"[{ts}] {msg}")

    def _toggle_theme(self, btn):
        mgr = Adw.StyleManager.get_default()
        self.dark_mode = not self.dark_mode
        mgr.set_color_scheme(Adw.ColorScheme.FORCE_DARK if self.dark_mode else Adw.ColorScheme.FORCE_LIGHT)

    def _add_domain(self, *args):
        domain = self.domain_entry.get_text().strip().lower()
        if not domain or domain in self.domains:
            return
        self.domains.append(domain)
        self.domain_entry.set_text("")
        self._check_domain(domain)

    def _remove_selected(self, *args):
        row = self.listbox.get_selected_row()
        if row and hasattr(row, "info"):
            d = row.info["domain"]
            self.domains.remove(d)
            self.results.pop(d, None)
            self.listbox.remove(row)
            self._clear_detail()
            self._set_status(f"Removed {d}")

    def _check_domain(self, domain):
        self._set_status(f"Checking {domain}...")
        def worker():
            info = fetch_cert_info(domain)
            GLib.idle_add(self._on_result, info)
        threading.Thread(target=worker, daemon=True).start()

    def _on_result(self, info):
        domain = info["domain"]
        self.results[domain] = info
        # Update or add row
        child = self.listbox.get_first_child()
        while child:
            if isinstance(child, CertRow) and child.info["domain"] == domain:
                idx = child.get_index()
                self.listbox.remove(child)
                row = CertRow(info)
                self.listbox.insert(row, idx)
                self._set_status(f"Updated {domain}")
                return
            child = child.get_next_sibling()
        row = CertRow(info)
        self.listbox.append(row)
        self._set_status(f"Added {domain}")

    def _on_row_selected(self, listbox, row):
        if not row or not hasattr(row, "info"):
            return
        self._show_detail(row.info)

    def _clear_detail(self):
        child = self.detail_box.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self.detail_box.remove(child)
            child = nxt
        lbl = Gtk.Label(label=_("Select a domain to view details"), xalign=0)
        lbl.add_css_class("dim-label")
        self.detail_box.append(lbl)

    def _show_detail(self, info):
        child = self.detail_box.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self.detail_box.remove(child)
            child = nxt

        def add_group(title, rows):
            grp = Adw.PreferencesGroup(title=title)
            for label, value in rows:
                row = Adw.ActionRow(title=label, subtitle=str(value))
                row.set_subtitle_selectable(True)
                grp.add(row)
            self.detail_box.append(grp)

        if info.get("error"):
            add_group(info["domain"], [(_("Error"), info["error"]), (_("Checked"), info.get("checked_at", ""))])
            return

        add_group(_("Certificate"), [
            (_("Common Name"), info.get("subject", {}).get("commonName", "?")),
            (_("Issuer (Org)"), info.get("issuer", {}).get("organizationName", "?")),
            (_("Issuer (CN)"), info.get("issuer", {}).get("commonName", "?")),
            (_("Serial"), info.get("serial", "?")),
            (_("Not Before"), info.get("not_before", "?")),
            (_("Not After"), info.get("not_after", "?")),
            (_("Days Until Expiry"), str(info.get("days_left", "?"))),
        ])
        add_group(_("Connection"), [
            (_("Protocol"), info.get("protocol", "?")),
            (_("Cipher Suite"), info.get("cipher_suite", "?")),
            (_("Cipher Bits"), str(info.get("cipher_bits", "?"))),
            (_("HSTS"), info.get("hsts", "?")),
        ])
        if info.get("sans"):
            add_group(_("Subject Alt Names"), [(san, "") for san in info["sans"]])
        add_group(_("Meta"), [(_("Checked At"), info.get("checked_at", ""))])

    def _refresh_all(self):
        for domain in self.domains:
            self._check_domain(domain)

    def _start_polling(self):
        def poll():
            self._refresh_all()
            return True
        self.poll_source = GLib.timeout_add_seconds(self.poll_interval, poll)

    def _export_json(self, *args):
        data = list(self.results.values())
        self._save_file("cert-watch-report.json", json.dumps(data, indent=2, default=str))

    def _export_csv(self, *args):
        if not self.results:
            return
        output = io.StringIO()
        fields = ["domain", "protocol", "cipher_suite", "cipher_bits", "not_before", "not_after", "days_left", "hsts", "error", "checked_at"]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for info in self.results.values():
            flat = {**info}
            flat["issuer"] = info.get("issuer", {}).get("organizationName", "")
            writer.writerow(flat)
        self._save_file("cert-watch-report.csv", output.getvalue())

    def _save_file(self, default_name, content):
        # Simple save to home
        path = os.path.expanduser(f"~/{default_name}")
        with open(path, "w") as f:
            f.write(content)
        self._set_status(f"Exported to {path}")

    def _show_about(self, *args):
        about = Adw.AboutDialog(
            application_name="Cert Watch",
            application_icon=APP_ID,
            version="0.1.0",
            developer_name="Daniel Nylander",
            license_type=Gtk.License.GPL_3_0,
            website="https://github.com/yeager/cert-watch",
            issue_url="https://github.com/yeager/cert-watch/issues",
            translator_credits="https://www.transifex.com/danielnylander/cert-watch/",
            developers=["Daniel Nylander"],
            copyright="© 2026 Daniel Nylander",
            comments=_("TLS Certificate Monitor"),
        )
        about.present(self)


class CertWatchApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def do_activate(self):
        self.settings = _load_settings()
        win = self.get_active_window()
        if not win:
            win = CertWatchWindow(self)
        win.present()
        if not self.settings.get("welcome_shown"):
            self._show_welcome(self if hasattr(self, "set_content") else win)


    def do_startup(self):
        Adw.Application.do_startup(self)
        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *a: self.quit())
        self.add_action(quit_action)
        self.set_accels_for_action("app.quit", ["<Control>q"])


def main():
    app = CertWatchApp()
    app.run()

if __name__ == "__main__":
    main()

    # ── Welcome Dialog ───────────────────────────────────────

    def _show_welcome(self, win):
        dialog = Adw.Dialog()
        dialog.set_title(_("Welcome"))
        dialog.set_content_width(420)
        dialog.set_content_height(480)

        page = Adw.StatusPage()
        page.set_icon_name("security-high-symbolic")
        page.set_title(_("Welcome to Certificate Watch"))
        page.set_description(_(
            "Monitor SSL/TLS certificates for expiration and security issues.\n\n✓ Track certificate expiry dates\n✓ Get notifications before certificates expire\n✓ Scan domains and IP addresses\n✓ Export reports"
        ))

        btn = Gtk.Button(label=_("Get Started"))
        btn.add_css_class("suggested-action")
        btn.add_css_class("pill")
        btn.set_halign(Gtk.Align.CENTER)
        btn.set_margin_top(12)
        btn.connect("clicked", self._on_welcome_close, dialog)
        page.set_child(btn)

        box = Adw.ToolbarView()
        hb = Adw.HeaderBar()
        hb.set_show_title(False)
        box.add_top_bar(hb)
        box.set_content(page)
        dialog.set_child(box)
        dialog.present(win)

    def _on_welcome_close(self, btn, dialog):
        self.settings["welcome_shown"] = True
        _save_settings(self.settings)
        dialog.close()

