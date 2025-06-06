import os
import sys
import json
import ctypes
import subprocess
import psutil
import platform
import tkinter as tk
from tkinter import messagebox, simpledialog
from datetime import datetime
import time
import threading
import hashlib
import winreg

class LockdownApp:
    def __init__(self, root=None, headless=False):
        self.headless = headless
        self.root = root
        
        # Configuration
        self.config_file = "config.json"
        self.password_hash_file = "password.hash"
        self.blocked_apps = []
        self.blocked_sites = []
        self.is_locked = False
        self.monitor_thread = None
        self.stop_monitoring = False
        
        # List of common browsers to close
        self.browser_list = [
            "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", 
            "brave.exe", "vivaldi.exe", "safari.exe", "iexplore.exe"
        ]
        
        # Load configuration
        self.load_config()
        
        # Check if password exists, if not create one (only in GUI mode)
        if not self.headless and not os.path.exists(self.password_hash_file):
            self.create_password()
        
        # Create UI if not in headless mode
        if not self.headless and self.root:
            self.root.title("Nubaid Lockdown")
            self.root.geometry("600x500")
            self.root.resizable(False, False)
            self.setup_ui()
        
        # Start monitoring if locked
        if self.is_locked:
            self.start_monitoring()
    
    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.blocked_apps = config.get('blocked_apps', [])
                    self.blocked_sites = config.get('blocked_sites', [])
                    self.is_locked = config.get('is_locked', False)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load configuration: {e}")
                self.blocked_apps = []
                self.blocked_sites = []
                self.is_locked = False
    
    def save_config(self):
        config = {
            'blocked_apps': self.blocked_apps,
            'blocked_sites': self.blocked_sites,
            'is_locked': self.is_locked
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")
    
    def create_password(self):
        password = simpledialog.askstring("Password Setup", "Enter a password for the lockdown app:", show='*')
        if password:
            confirm = simpledialog.askstring("Password Setup", "Confirm password:", show='*')
            if password == confirm:
                # Hash the password and save it
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                with open(self.password_hash_file, 'w') as f:
                    f.write(password_hash)
                messagebox.showinfo("Success", "Password has been set successfully!")
            else:
                messagebox.showerror("Error", "Passwords do not match. Please try again.")
                self.create_password()
        else:
            messagebox.showerror("Error", "Password cannot be empty!")
            self.create_password()
    
    def verify_password(self, entered_password):
        try:
            with open(self.password_hash_file, 'r') as f:
                stored_hash = f.read().strip()
            entered_hash = hashlib.sha256(entered_password.encode()).hexdigest()
            return entered_hash == stored_hash
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify password: {e}")
            return False
    
    def setup_ui(self):
        # Main frame
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Status section
        status_frame = tk.LabelFrame(main_frame, text="Status", padx=10, pady=10)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.status_label = tk.Label(
            status_frame, 
            text="LOCKED" if self.is_locked else "UNLOCKED",
            fg="red" if self.is_locked else "green",
            font=("Arial", 16, "bold")
        )
        self.status_label.pack()
        
        # Action buttons
        actions_frame = tk.Frame(main_frame)
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.lock_button = tk.Button(
            actions_frame, 
            text="Lock System", 
            command=self.lock_system,
            state=tk.NORMAL if not self.is_locked else tk.DISABLED,
            bg="#ff6666" if not self.is_locked else "#cccccc",
            width=15, height=2
        )
        self.lock_button.pack(side=tk.LEFT, padx=5)
        
        self.unlock_button = tk.Button(
            actions_frame, 
            text="Unlock System", 
            command=self.unlock_system,
            state=tk.NORMAL if self.is_locked else tk.DISABLED,
            bg="#66ff66" if self.is_locked else "#cccccc",
            width=15, height=2
        )
        self.unlock_button.pack(side=tk.RIGHT, padx=5)
        
        # Applications section
        apps_frame = tk.LabelFrame(main_frame, text="Blocked Applications", padx=10, pady=10)
        apps_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.apps_listbox = tk.Listbox(apps_frame, selectmode=tk.SINGLE, height=5)
        self.apps_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        apps_scrollbar = tk.Scrollbar(apps_frame)
        apps_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.apps_listbox.config(yscrollcommand=apps_scrollbar.set)
        apps_scrollbar.config(command=self.apps_listbox.yview)
        
        # Populate the apps listbox
        for app in self.blocked_apps:
            self.apps_listbox.insert(tk.END, app)
        
        # App buttons
        app_buttons_frame = tk.Frame(main_frame)
        app_buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        add_app_button = tk.Button(app_buttons_frame, text="Add Application", command=self.add_application)
        add_app_button.pack(side=tk.LEFT, padx=5)
        
        remove_app_button = tk.Button(app_buttons_frame, text="Remove Application", command=self.remove_application)
        remove_app_button.pack(side=tk.RIGHT, padx=5)
        
        # Websites section
        sites_frame = tk.LabelFrame(main_frame, text="Blocked Websites", padx=10, pady=10)
        sites_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.sites_listbox = tk.Listbox(sites_frame, selectmode=tk.SINGLE, height=5)
        self.sites_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        sites_scrollbar = tk.Scrollbar(sites_frame)
        sites_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.sites_listbox.config(yscrollcommand=sites_scrollbar.set)
        sites_scrollbar.config(command=self.sites_listbox.yview)
        
        # Populate the sites listbox
        for site in self.blocked_sites:
            self.sites_listbox.insert(tk.END, site)
        
        # Site buttons
        site_buttons_frame = tk.Frame(main_frame)
        site_buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        add_site_button = tk.Button(site_buttons_frame, text="Add Website", command=self.add_website)
        add_site_button.pack(side=tk.LEFT, padx=5)
        
        remove_site_button = tk.Button(site_buttons_frame, text="Remove Website", command=self.remove_website)
        remove_site_button.pack(side=tk.RIGHT, padx=5)
        
        # Settings section
        settings_frame = tk.Frame(main_frame)
        settings_frame.pack(fill=tk.X, padx=5, pady=10)
        
        change_password_button = tk.Button(settings_frame, text="Change Password", command=self.change_password)
        change_password_button.pack(side=tk.LEFT, padx=5)
        
        exit_button = tk.Button(settings_frame, text="Exit", command=self.exit_app)
        exit_button.pack(side=tk.RIGHT, padx=5)
    
    def add_application(self):
        if self.is_locked:
            messagebox.showinfo("Info", "System is locked. Unlock first to make changes.")
            return
            
        app_name = simpledialog.askstring("Add Application", "Enter application name (e.g., notepad.exe):")
        if app_name:
            if app_name not in self.blocked_apps:
                self.blocked_apps.append(app_name)
                self.apps_listbox.insert(tk.END, app_name)
                self.save_config()
                messagebox.showinfo("Success", f"Added {app_name} to blocked applications.")
            else:
                messagebox.showinfo("Info", f"{app_name} is already in the blocked list.")
    
    def remove_application(self):
        if self.is_locked:
            messagebox.showinfo("Info", "System is locked. Unlock first to make changes.")
            return
            
        selected = self.apps_listbox.curselection()
        if selected:
            app_name = self.apps_listbox.get(selected[0])
            self.blocked_apps.remove(app_name)
            self.apps_listbox.delete(selected[0])
            self.save_config()
            messagebox.showinfo("Success", f"Removed {app_name} from blocked applications.")
        else:
            messagebox.showinfo("Info", "Please select an application to remove.")
    
    def add_website(self):
        if self.is_locked:
            messagebox.showinfo("Info", "System is locked. Unlock first to make changes.")
            return
            
        website = simpledialog.askstring("Add Website", "Enter website to block (e.g., facebook.com):")
        if website:
            if website not in self.blocked_sites:
                self.blocked_sites.append(website)
                self.sites_listbox.insert(tk.END, website)
                self.save_config()
                messagebox.showinfo("Success", f"Added {website} to blocked websites.")
            else:
                messagebox.showinfo("Info", f"{website} is already in the blocked list.")
    
    def remove_website(self):
        if self.is_locked:
            messagebox.showinfo("Info", "System is locked. Unlock first to make changes.")
            return
            
        selected = self.sites_listbox.curselection()
        if selected:
            website = self.sites_listbox.get(selected[0])
            self.blocked_sites.remove(website)
            self.sites_listbox.delete(selected[0])
            self.save_config()
            messagebox.showinfo("Success", f"Removed {website} from blocked websites.")
        else:
            messagebox.showinfo("Info", "Please select a website to remove.")
    
    def lock_system(self):
        """Lock the system either in GUI or headless mode"""
        # Close all open browsers before locking
        closed_browsers = self.close_browsers()
        
        self.is_locked = True
        
        # Update UI if in GUI mode
        if not self.headless and self.root:
            self.status_label.config(text="LOCKED", fg="red")
            self.lock_button.config(state=tk.DISABLED, bg="#cccccc")
            self.unlock_button.config(state=tk.NORMAL, bg="#66ff66")
        
        self.save_config()
        
        # Block websites in hosts file
        self.block_websites()
        
        # Start monitoring blocked applications
        self.start_monitoring()
        
        # Show message about closed browsers if in GUI mode
        if not self.headless and self.root and closed_browsers:
            browsers_str = ", ".join(closed_browsers)
            messagebox.showinfo(
                "Browsers Closed", 
                f"The following browsers were closed: {browsers_str}\n\n"
                "When you reopen them, the website blocks will be active."
            )
        
        # Show success message if in GUI mode
        if not self.headless and self.root:
            messagebox.showinfo("Lockdown", "System is now locked!")
            
        return True
    
    def close_browsers(self):
        """Close all running browsers to ensure website blocks take effect"""
        closed_browsers = []
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                process_name = proc.info['name'].lower()
                
                # Check if this is a browser we should close
                for browser in self.browser_list:
                    if browser.lower() in process_name:
                        try:
                            # Try to terminate the browser process
                            process = psutil.Process(proc.info['pid'])
                            process.terminate()
                            
                            # Wait for it to actually terminate
                            process.wait(timeout=3)
                            
                            # Add to our list of closed browsers
                            if browser not in closed_browsers:
                                closed_browsers.append(browser)
                                
                            print(f"Closed browser: {process_name}")
                        except Exception as e:
                            print(f"Failed to close browser {process_name}: {e}")
            
            # Short delay to ensure browsers have time to close
            time.sleep(1)
            return closed_browsers
            
        except Exception as e:
            print(f"Error in close_browsers: {e}")
            return closed_browsers
    
    def unlock_system(self):
        """Unlock system with GUI interaction"""
        if self.headless:
            # This should not be called in headless mode
            return False
            
        password = simpledialog.askstring("Unlock System", "Enter password to unlock:", show='*')
        if password and self.verify_password(password):
            self._perform_unlock()
            return True
        else:
            if not self.headless and self.root:
                messagebox.showerror("Error", "Incorrect password!")
            return False
    
    def unlock_system_headless(self, password):
        """Unlock system without GUI interaction, using provided password"""
        if self.verify_password(password):
            self._perform_unlock()
            return True
        return False
    
    def _perform_unlock(self):
        """Internal method to perform the actual unlock operations"""
        self.is_locked = False
        
        # Update UI if in GUI mode
        if not self.headless and self.root:
            self.status_label.config(text="UNLOCKED", fg="green")
            self.lock_button.config(state=tk.NORMAL, bg="#ff6666")
            self.unlock_button.config(state=tk.DISABLED, bg="#cccccc")
        
        self.save_config()
        
        # Unblock websites
        self.unblock_websites()
        
        # Stop monitoring
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.stop_monitoring = True
            self.monitor_thread.join(1)
        
        # Show success message if in GUI mode
        if not self.headless and self.root:
            messagebox.showinfo("Lockdown", "System is now unlocked!")
    
    def block_websites(self):
        """Block websites using hosts file"""
        if not self.blocked_sites:
            return
            
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        
        try:
            # Check if we have admin rights and show a clear error if not
            if not ctypes.windll.shell32.IsUserAnAdmin():
                if not self.headless and self.root:
                    messagebox.showerror(
                        "Admin Rights Required", 
                        "Website blocking failed! You must run this application as administrator.\n\n"
                        "Right-click on the application and select 'Run as administrator'."
                    )
                return
            
            # Create a backup if it doesn't exist
            try:
                if not os.path.exists(hosts_path + ".backup"):
                    with open(hosts_path, 'r') as f:
                        hosts_content = f.read()
                    with open(hosts_path + ".backup", 'w') as f:
                        f.write(hosts_content)
            except Exception as e:
                if not self.headless and self.root:
                    messagebox.showerror("Error", f"Failed to create hosts file backup: {e}")
                return
            
            # Read current hosts file
            try:
                with open(hosts_path, 'r') as f:
                    hosts_content = f.read()
            except Exception as e:
                if not self.headless and self.root:
                    messagebox.showerror("Error", f"Failed to read hosts file: {e}")
                return
            
            # Add our block section if not present
            if "# START NUBAID LOCKDOWN BLOCK" not in hosts_content:
                hosts_content += "\n\n# START NUBAID LOCKDOWN BLOCK\n# END NUBAID LOCKDOWN BLOCK\n"
            
            # Split content at our markers
            parts = hosts_content.split("# START NUBAID LOCKDOWN BLOCK")
            before_block = parts[0]
            after_parts = parts[1].split("# END NUBAID LOCKDOWN BLOCK")
            if len(after_parts) > 1:
                after_block = after_parts[1]
            else:
                after_block = "\n"
            
            # Create new block content
            block_content = "# START NUBAID LOCKDOWN BLOCK\n"
            for site in self.blocked_sites:
                if not site.strip():
                    continue
                # Make sure the site name is clean
                site = site.strip().lower()
                if not site.startswith("www."):
                    block_content += f"127.0.0.1 {site}\n"
                    block_content += f"127.0.0.1 www.{site}\n"
                else:
                    block_content += f"127.0.0.1 {site}\n"
                    block_content += f"127.0.0.1 {site[4:]}\n"  # Remove www. prefix
            block_content += "# END NUBAID LOCKDOWN BLOCK\n"
            
            # Combine everything
            new_hosts_content = before_block + block_content + after_block
            
            # Write back to hosts file
            try:
                with open(hosts_path, 'w') as f:
                    f.write(new_hosts_content)
                print(f"Successfully wrote to hosts file. Blocked sites: {self.blocked_sites}")
            except Exception as e:
                if not self.headless and self.root:
                    messagebox.showerror("Error", f"Failed to write to hosts file: {e}")
                return
                
            # Flush DNS cache
            try:
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True, check=True)
                print("Successfully flushed DNS cache")
            except Exception as e:
                if not self.headless and self.root:
                    messagebox.showerror("Error", f"Failed to flush DNS cache: {e}\nTry restarting your browser.")
                
            # Successfully blocked websites
            if not self.headless and self.root:
                messagebox.showinfo("Success", "Websites have been blocked. You may need to restart your browser for changes to take effect.")
                
        except Exception as e:
            if not self.headless and self.root:
                messagebox.showerror("Error", f"Failed to block websites: {e}")
    
    def unblock_websites(self):
        """Unblock websites by restoring hosts file"""
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        
        try:
            # Check if we have admin rights and show a clear error if not
            if not ctypes.windll.shell32.IsUserAnAdmin():
                if not self.headless and self.root:
                    messagebox.showerror(
                        "Admin Rights Required", 
                        "Website unblocking failed! You must run this application as administrator.\n\n"
                        "Right-click on the application and select 'Run as administrator'."
                    )
                return
            
            # Check if backup exists and restore it
            if os.path.exists(hosts_path + ".backup"):
                try:
                    with open(hosts_path + ".backup", 'r') as f:
                        hosts_content = f.read()
                    with open(hosts_path, 'w') as f:
                        f.write(hosts_content)
                    print("Successfully restored hosts file from backup")
                except Exception as e:
                    if not self.headless and self.root:
                        messagebox.showerror("Error", f"Failed to restore hosts file from backup: {e}")
                    return
            else:
                # Read current hosts file
                try:
                    with open(hosts_path, 'r') as f:
                        hosts_content = f.read()
                except Exception as e:
                    if not self.headless and self.root:
                        messagebox.showerror("Error", f"Failed to read hosts file: {e}")
                    return
                
                # Split content at our markers
                if "# START NUBAID LOCKDOWN BLOCK" in hosts_content:
                    parts = hosts_content.split("# START NUBAID LOCKDOWN BLOCK")
                    before_block = parts[0]
                    after_parts = parts[1].split("# END NUBAID LOCKDOWN BLOCK")
                    if len(after_parts) > 1:
                        after_block = after_parts[1]
                    else:
                        after_block = "\n"
                    
                    # Combine everything without our block
                    new_hosts_content = before_block + after_block
                    
                    # Write back to hosts file
                    try:
                        with open(hosts_path, 'w') as f:
                            f.write(new_hosts_content)
                        print("Successfully removed block section from hosts file")
                    except Exception as e:
                        if not self.headless and self.root:
                            messagebox.showerror("Error", f"Failed to write to hosts file: {e}")
                        return
            
            # Flush DNS cache
            try:
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True, check=True)
                print("Successfully flushed DNS cache")
            except Exception as e:
                if not self.headless and self.root:
                    messagebox.showerror("Error", f"Failed to flush DNS cache: {e}\nTry restarting your browser.")
                
            # Successfully unblocked websites
            if not self.headless and self.root:
                messagebox.showinfo("Success", "Websites have been unblocked. You may need to restart your browser for changes to take effect.")
                
        except Exception as e:
            if not self.headless and self.root:
                messagebox.showerror("Error", f"Failed to unblock websites: {e}")
    
    def start_monitoring(self):
        if self.monitor_thread and self.monitor_thread.is_alive():
            return
            
        self.stop_monitoring = False
        self.monitor_thread = threading.Thread(target=self.monitor_processes)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def monitor_processes(self):
        while not self.stop_monitoring:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    proc_name = proc.info['name'].lower()
                    for blocked_app in self.blocked_apps:
                        if blocked_app.lower() in proc_name:
                            try:
                                process = psutil.Process(proc.info['pid'])
                                process.terminate()
                                print(f"Terminated blocked application: {proc_name}")
                            except Exception as e:
                                print(f"Failed to terminate {proc_name}: {e}")
            except Exception as e:
                print(f"Error in monitoring thread: {e}")
                
            time.sleep(1)  # Check every second
    
    def change_password(self):
        current_password = simpledialog.askstring("Change Password", "Enter current password:", show='*')
        if current_password and self.verify_password(current_password):
            new_password = simpledialog.askstring("Change Password", "Enter new password:", show='*')
            if new_password:
                confirm_password = simpledialog.askstring("Change Password", "Confirm new password:", show='*')
                if new_password == confirm_password:
                    # Hash and save the new password
                    password_hash = hashlib.sha256(new_password.encode()).hexdigest()
                    with open(self.password_hash_file, 'w') as f:
                        f.write(password_hash)
                    messagebox.showinfo("Success", "Password has been changed successfully!")
                else:
                    messagebox.showerror("Error", "New passwords do not match. Please try again.")
        else:
            messagebox.showerror("Error", "Incorrect current password!")
    
    def exit_app(self):
        if self.is_locked:
            password = simpledialog.askstring("Exit Application", "Enter password to exit:", show='*')
            if not password or not self.verify_password(password):
                messagebox.showerror("Error", "Incorrect password! Cannot exit.")
                return
        
        if messagebox.askyesno("Exit", "Are you sure you want to exit the application?"):
            # Stop monitoring thread if running
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.stop_monitoring = True
                self.monitor_thread.join(1)
            
            # Save configuration
            self.save_config()
            
            # Exit application if in GUI mode
            if self.root:
                self.root.destroy()

    def update_blocked_apps(self, apps_list):
        """Update the list of blocked applications"""
        self.blocked_apps = apps_list
        self.save_config()
        
    def update_blocked_sites(self, sites_list):
        """Update the list of blocked websites"""
        self.blocked_sites = sites_list
        self.save_config()

def run_as_admin():
    """Restart the program with admin rights if needed"""
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
        else:
            # Re-run the program with admin rights
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1
            )
            return False
    except Exception as e:
        print(f"Error in run_as_admin: {e}")
        # If we can't check or request admin rights, just continue
        return True

def main():
    # Try to run as admin
    if not run_as_admin():
        sys.exit(0)
        
    root = tk.Tk()
    app = LockdownApp(root)
    root.mainloop()

if __name__ == "__main__":
    main() 