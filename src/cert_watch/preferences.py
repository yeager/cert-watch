"""Preferences dialog for email notification settings."""
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio
import gettext

_ = gettext.gettext


class EmailPreferencesDialog(Adw.Dialog):
    """Dialog for configuring email notification settings."""
    
    def __init__(self, parent_window, settings, on_save_callback=None):
        """Initialize preferences dialog.
        
        Args:
            parent_window: Parent window
            settings: Current settings dictionary
            on_save_callback: Callback function called when settings are saved
        """
        super().__init__()
        self.settings = settings.copy()
        self.on_save_callback = on_save_callback
        
        self.set_title(_("Email Notifications"))
        self.set_content_width(500)
        self.set_content_height(600)
        self.set_modal(True)
        
        # Main container
        toolbar_view = Adw.ToolbarView()
        
        # Header bar
        header = Adw.HeaderBar()
        header.set_show_title(False)
        
        # Cancel button
        cancel_btn = Gtk.Button(label=_("Cancel"))
        cancel_btn.connect("clicked", lambda *args: self.close())
        header.pack_start(cancel_btn)
        
        # Save button
        self.save_btn = Gtk.Button(label=_("Save"))
        self.save_btn.add_css_class("suggested-action")
        self.save_btn.connect("clicked", self._on_save)
        header.pack_end(self.save_btn)
        
        toolbar_view.add_top_bar(header)
        
        # Content
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content.set_margin_start(20)
        content.set_margin_end(20)
        content.set_margin_top(20)
        content.set_margin_bottom(20)
        
        # Enable/disable switch
        self.enable_switch = Gtk.Switch()
        self.enable_switch.set_active(self.settings.get('email_notifications_enabled', False))
        self.enable_switch.connect("state-set", self._on_enable_toggled)
        
        enable_row = Adw.ActionRow()
        enable_row.set_title(_("Enable Email Notifications"))
        enable_row.set_subtitle(_("Send email alerts when certificates are about to expire"))
        enable_row.add_suffix(self.enable_switch)
        
        enable_group = Adw.PreferencesGroup()
        enable_group.add(enable_row)
        content.append(enable_group)
        
        # SMTP Settings
        smtp_group = Adw.PreferencesGroup()
        smtp_group.set_title(_("SMTP Server Settings"))
        smtp_group.set_description(_("Configure your email server settings"))
        
        # SMTP Server
        self.smtp_server_entry = Gtk.Entry()
        self.smtp_server_entry.set_placeholder_text("smtp.gmail.com")
        self.smtp_server_entry.set_text(self.settings.get('smtp_server', ''))
        smtp_server_row = Adw.ActionRow()
        smtp_server_row.set_title(_("SMTP Server"))
        smtp_server_row.set_subtitle(_("Hostname of your email server"))
        smtp_server_row.add_suffix(self.smtp_server_entry)
        smtp_group.add(smtp_server_row)
        
        # SMTP Port
        self.smtp_port_entry = Gtk.Entry()
        self.smtp_port_entry.set_placeholder_text("587")
        self.smtp_port_entry.set_text(str(self.settings.get('smtp_port', 587)))
        self.smtp_port_entry.set_input_purpose(Gtk.InputPurpose.DIGITS)
        smtp_port_row = Adw.ActionRow()
        smtp_port_row.set_title(_("SMTP Port"))
        smtp_port_row.set_subtitle(_("Usually 587 for TLS or 465 for SSL"))
        smtp_port_row.add_suffix(self.smtp_port_entry)
        smtp_group.add(smtp_port_row)
        
        # Use TLS
        self.tls_switch = Gtk.Switch()
        self.tls_switch.set_active(self.settings.get('use_tls', True))
        tls_row = Adw.ActionRow()
        tls_row.set_title(_("Use TLS Encryption"))
        tls_row.set_subtitle(_("Recommended for secure email transmission"))
        tls_row.add_suffix(self.tls_switch)
        smtp_group.add(tls_row)
        
        content.append(smtp_group)
        
        # Authentication
        auth_group = Adw.PreferencesGroup()
        auth_group.set_title(_("Authentication"))
        
        # Username
        self.username_entry = Gtk.Entry()
        self.username_entry.set_placeholder_text("your-email@example.com")
        self.username_entry.set_text(self.settings.get('smtp_user', ''))
        username_row = Adw.ActionRow()
        username_row.set_title(_("Username/Email"))
        username_row.set_subtitle(_("Your email address for SMTP authentication"))
        username_row.add_suffix(self.username_entry)
        auth_group.add(username_row)
        
        # Password
        self.password_entry = Gtk.PasswordEntry()
        self.password_entry.set_placeholder_text(_("Enter password or app password"))
        self.password_entry.set_text(self.settings.get('smtp_password', ''))
        password_row = Adw.ActionRow()
        password_row.set_title(_("Password"))
        password_row.set_subtitle(_("Use an app-specific password for Gmail/Outlook"))
        password_row.add_suffix(self.password_entry)
        auth_group.add(password_row)
        
        content.append(auth_group)
        
        # Email Addresses
        email_group = Adw.PreferencesGroup()
        email_group.set_title(_("Email Addresses"))
        
        # From Email
        self.from_email_entry = Gtk.Entry()
        self.from_email_entry.set_placeholder_text("cert-watch@example.com")
        self.from_email_entry.set_text(self.settings.get('from_email', ''))
        from_row = Adw.ActionRow()
        from_row.set_title(_("From Email"))
        from_row.set_subtitle(_("Email address that appears as sender"))
        from_row.add_suffix(self.from_email_entry)
        email_group.add(from_row)
        
        # To Emails
        self.to_emails_entry = Gtk.Entry()
        self.to_emails_entry.set_placeholder_text("admin@example.com, security@example.com")
        to_emails = self.settings.get('to_emails', [])
        if isinstance(to_emails, list):
            self.to_emails_entry.set_text(", ".join(to_emails))
        else:
            self.to_emails_entry.set_text(str(to_emails))
        to_row = Adw.ActionRow()
        to_row.set_title(_("To Emails"))
        to_row.set_subtitle(_("Comma-separated list of recipient email addresses"))
        to_row.add_suffix(self.to_emails_entry)
        email_group.add(to_row)
        
        content.append(email_group)
        
        # Warning Settings
        warning_group = Adw.PreferencesGroup()
        warning_group.set_title(_("Warning Thresholds"))
        warning_group.set_description(_("Configure when to send expiry warnings"))
        
        # Warning days
        self.warning_days_entry = Gtk.Entry()
        self.warning_days_entry.set_placeholder_text("7, 3, 1")
        warning_days = self.settings.get('warning_days', [7, 3, 1])
        if isinstance(warning_days, list):
            self.warning_days_entry.set_text(", ".join(str(d) for d in warning_days))
        else:
            self.warning_days_entry.set_text(str(warning_days))
        warning_row = Adw.ActionRow()
        warning_row.set_title(_("Warning Days"))
        warning_row.set_subtitle(_("Days before expiry to send warnings (comma-separated)"))
        warning_row.add_suffix(self.warning_days_entry)
        warning_group.add(warning_row)
        
        content.append(warning_group)
        
        # Test button
        test_group = Adw.PreferencesGroup()
        test_btn = Gtk.Button(label=_("Send Test Email"))
        test_btn.add_css_class("pill")
        test_btn.set_halign(Gtk.Align.CENTER)
        test_btn.set_margin_top(10)
        test_btn.connect("clicked", self._send_test_email)
        test_group.add(test_btn)
        content.append(test_group)
        
        # Scrolled window
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.set_child(content)
        
        toolbar_view.set_content(scrolled)
        self.set_child(toolbar_view)
        
        # Initial state
        self._update_sensitivity()
        
        # Connect entry changes to validation
        for entry in [self.smtp_server_entry, self.username_entry, self.password_entry, 
                      self.from_email_entry, self.to_emails_entry]:
            entry.connect("changed", self._validate_form)
        
        self.present(parent_window)
    
    def _on_enable_toggled(self, switch, state):
        """Handle enable/disable toggle."""
        self._update_sensitivity()
        return False
    
    def _update_sensitivity(self):
        """Update form sensitivity based on enable switch."""
        enabled = self.enable_switch.get_active()
        
        # Enable/disable all form elements
        for widget in [self.smtp_server_entry, self.smtp_port_entry, self.tls_switch,
                       self.username_entry, self.password_entry, self.from_email_entry,
                       self.to_emails_entry, self.warning_days_entry]:
            widget.set_sensitive(enabled)
        
        self._validate_form()
    
    def _validate_form(self, *args):
        """Validate form and update save button sensitivity."""
        if not self.enable_switch.get_active():
            self.save_btn.set_sensitive(True)
            return
        
        # Check required fields
        required_fields = [
            self.smtp_server_entry.get_text().strip(),
            self.username_entry.get_text().strip(),
            self.password_entry.get_text().strip(),
            self.from_email_entry.get_text().strip(),
            self.to_emails_entry.get_text().strip()
        ]
        
        self.save_btn.set_sensitive(all(required_fields))
    
    def _send_test_email(self, button):
        """Send a test email to verify settings."""
        # Save current form data to temporary config
        temp_config = self._get_form_data()
        
        if not temp_config['email_notifications_enabled']:
            self._show_message(_("Email notifications are disabled"))
            return
        
        # Validate required fields
        required = ['smtp_server', 'smtp_user', 'smtp_password', 'from_email', 'to_emails']
        if not all(temp_config.get(field) for field in required):
            self._show_message(_("Please fill in all required fields"))
            return
        
        # Import here to avoid circular imports
        from .email_notifier import EmailNotifier
        
        button.set_sensitive(False)
        button.set_label(_("Sending..."))
        
        def send_test():
            """Send test email in thread."""
            try:
                # Create test certificate info
                test_cert_info = {
                    'domain': 'test.example.com',
                    'days_left': 7,
                    'issuer': {'organizationName': 'Test CA'},
                    'not_after': 'Mar 27 12:00:00 2026 GMT',
                    'protocol': 'TLSv1.3'
                }
                
                notifier = EmailNotifier(temp_config)
                success = notifier.send_warning(test_cert_info, 7)
                
                # Update UI in main thread
                from gi.repository import GLib
                GLib.idle_add(self._on_test_complete, success, button)
                
            except Exception as e:
                from gi.repository import GLib
                GLib.idle_add(self._on_test_error, str(e), button)
        
        import threading
        threading.Thread(target=send_test, daemon=True).start()
    
    def _on_test_complete(self, success, button):
        """Handle test email completion."""
        button.set_sensitive(True)
        button.set_label(_("Send Test Email"))
        
        if success:
            self._show_message(_("Test email sent successfully!"), success=True)
        else:
            self._show_message(_("Failed to send test email. Check your settings and try again."))
    
    def _on_test_error(self, error, button):
        """Handle test email error."""
        button.set_sensitive(True)
        button.set_label(_("Send Test Email"))
        self._show_message(f"{_('Test failed')}: {error}")
    
    def _show_message(self, message, success=False):
        """Show a temporary message to the user."""
        toast = Adw.Toast(title=message)
        toast.set_timeout(3)
        
        # Find the toast overlay (create if needed)
        overlay = getattr(self, '_toast_overlay', None)
        if not overlay:
            # Create toast overlay if it doesn't exist
            overlay = Adw.ToastOverlay()
            self._toast_overlay = overlay
            
            # Replace current child with overlay
            current_child = self.get_child()
            self.set_child(overlay)
            overlay.set_child(current_child)
        
        overlay.add_toast(toast)
    
    def _get_form_data(self):
        """Get current form data as dictionary."""
        # Parse to_emails
        to_emails_text = self.to_emails_entry.get_text().strip()
        to_emails = [email.strip() for email in to_emails_text.split(',') if email.strip()]
        
        # Parse warning days
        warning_days_text = self.warning_days_entry.get_text().strip()
        warning_days = []
        try:
            warning_days = [int(d.strip()) for d in warning_days_text.split(',') if d.strip()]
            if not warning_days:
                warning_days = [7, 3, 1]
        except ValueError:
            warning_days = [7, 3, 1]
        
        # Parse port
        try:
            smtp_port = int(self.smtp_port_entry.get_text().strip() or "587")
        except ValueError:
            smtp_port = 587
        
        return {
            'email_notifications_enabled': self.enable_switch.get_active(),
            'smtp_server': self.smtp_server_entry.get_text().strip(),
            'smtp_port': smtp_port,
            'use_tls': self.tls_switch.get_active(),
            'smtp_user': self.username_entry.get_text().strip(),
            'smtp_password': self.password_entry.get_text().strip(),
            'from_email': self.from_email_entry.get_text().strip(),
            'to_emails': to_emails,
            'warning_days': warning_days
        }
    
    def _on_save(self, button):
        """Save settings and close dialog."""
        form_data = self._get_form_data()
        
        # Update settings
        self.settings.update(form_data)
        
        # Call callback if provided
        if self.on_save_callback:
            self.on_save_callback(self.settings)
        
        self.close()