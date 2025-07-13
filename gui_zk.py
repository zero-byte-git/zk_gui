import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Toplevel, Label, Entry, Button
from zk import ZK, const
import sqlite3
from datetime import datetime, timedelta
import os
import logging
from datetime import datetime
import time



# Custom adapter to store datetime as ISO string
def adapt_datetime(dt):
    return dt.isoformat()

# Custom converter to parse ISO string back to datetime
def convert_datetime(s):
    return datetime.fromisoformat(s.decode('utf-8'))

sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("TIMESTAMP", convert_datetime)




# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app_debug.log"),
        logging.StreamHandler()
    ]
)


def ask_datetime(parent, title):
    result = [None]
    
    def on_ok():
        date_str = date_entry.get()
        time_str = time_entry.get()
        
        try:
            # Validate date
            date_part = datetime.strptime(date_str, "%Y-%m-%d")
            # Validate time
            time_part = datetime.strptime(time_str, "%H:%M").time()
            
            combined = datetime.combine(date_part.date(), time_part)
            result[0] = combined
            dialog.destroy()
        except ValueError as e:
            messagebox.showerror("Invalid Format", "Please use:\nDate: YYYY-MM-DD\nTime: HH:MM (24-hour format)")
    
    dialog = Toplevel(parent)
    dialog.title(title)
    dialog.transient(parent)
    dialog.grab_set()
    
    Label(dialog, text="Date (YYYY-MM-DD):").grid(row=0, column=0, padx=5, pady=5)
    date_entry = Entry(dialog)
    date_entry.grid(row=0, column=1, padx=5, pady=5)
    date_entry.insert(0, (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d"))
    
    Label(dialog, text="Time (HH:MM):").grid(row=1, column=0, padx=5, pady=5)
    time_entry = Entry(dialog)
    time_entry.grid(row=1, column=1, padx=5, pady=5)
    time_entry.insert(0, "00:00")
    
    Button(dialog, text="OK", command=on_ok).grid(row=2, column=0, padx=5, pady=5)
    Button(dialog, text="Cancel", command=dialog.destroy).grid(row=2, column=1, padx=5, pady=5)
    
    parent.wait_window(dialog)
    return result[0]
    
# Update refresh_selectors() to populate listbox:
def refresh_selectors(self):
    c = self.conn.cursor()
    
    # Refresh user list
    c.execute("SELECT id, name FROM users")
    users = c.fetchall()
    self.user_listbox.delete(0, tk.END)
    for u in users:
        self.user_listbox.insert(tk.END, f"{u[0]} - {u[1]}")
    
    # Refresh device selector
    c.execute("SELECT id, name FROM devices")
    devices = c.fetchall()
    self.device_selector['values'] = [f"{d[0]} - {d[1]}" for d in devices]

# Database Setup
def init_db():
    conn = sqlite3.connect('device_management.db')
    c = conn.cursor()
    
    # Create devices table
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT,
                  ip TEXT UNIQUE,
                  port INTEGER,
                  password TEXT,
                  description TEXT)''')
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  uid INTEGER UNIQUE,
                  name TEXT,
                  password TEXT,
                  group_id TEXT,
                  user_id TEXT,
                  created_at TIMESTAMP)''')
    
    # Create device access table with expiration
    c.execute('''CREATE TABLE IF NOT EXISTS device_access
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_id INTEGER NOT NULL,
                expiration_date TIMESTAMP NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(device_id) REFERENCES devices(id),
                UNIQUE(user_id, device_id))''')
    
    conn.commit()
    conn.close()

class DeviceManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Device & User Access Control System")
        self.conn = sqlite3.connect('device_management.db', detect_types=sqlite3.PARSE_DECLTYPES)
        self.current_device_conn = None
        self.create_widgets()
        self.load_devices()
        self.load_users()
        self.start_expiration_checker()
        self.current_user_id = None
        
    def create_widgets(self):
        # Create tabs
        self.tabControl = ttk.Notebook(self.root)
        
        # Device Tab
        self.device_tab = ttk.Frame(self.tabControl)
        self.tabControl.add(self.device_tab, text='Devices')
        
        # User Tab
        self.user_tab = ttk.Frame(self.tabControl)
        self.tabControl.add(self.user_tab, text='Users & Access')
        
        self.tabControl.pack(expand=1, fill="both")
        
        # Device Management UI
        self.create_device_ui()
        # User Management UI
        self.create_user_ui()
    
    def create_device_ui(self):
        # Device Form
        device_form = ttk.LabelFrame(self.device_tab, text="Add/Edit Device")
        device_form.pack(pady=10, padx=10, fill="x")
        
        self.device_name = tk.StringVar()
        self.device_ip = tk.StringVar()
        self.device_port = tk.IntVar(value=4370)
        self.device_password = tk.StringVar()
        self.device_desc = tk.StringVar()
        
        ttk.Label(device_form, text="Name").grid(row=0, column=0, padx=5, pady=2)
        ttk.Entry(device_form, textvariable=self.device_name).grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        
        ttk.Label(device_form, text="IP Address").grid(row=0, column=2, padx=5, pady=2)
        ttk.Entry(device_form, textvariable=self.device_ip).grid(row=0, column=3, padx=5, pady=2, sticky="ew")
        
        ttk.Label(device_form, text="Port").grid(row=1, column=0, padx=5, pady=2)
        ttk.Entry(device_form, textvariable=self.device_port).grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        
        ttk.Label(device_form, text="Password").grid(row=1, column=2, padx=5, pady=2)
        ttk.Entry(device_form, textvariable=self.device_password, show="*").grid(row=1, column=3, padx=5, pady=2, sticky="ew")
        
        ttk.Label(device_form, text="Description").grid(row=2, column=0, padx=5, pady=2)
        ttk.Entry(device_form, textvariable=self.device_desc).grid(row=2, column=1, columnspan=3, padx=5, pady=2, sticky="ew")
        
        ttk.Button(device_form, text="Save Device", command=self.save_device).grid(row=3, column=3, padx=5, pady=5, sticky="e")
        
        # Device List
        device_list = ttk.LabelFrame(self.device_tab, text="Registered Devices")
        device_list.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.device_tree = ttk.Treeview(device_list, columns=("ID", "Name", "IP", "Port", "Status"), show='headings')
        self.device_tree.heading("ID", text="ID")
        self.device_tree.heading("Name", text="Name")
        self.device_tree.heading("IP", text="IP Address")
        self.device_tree.heading("Port", text="Port")
        self.device_tree.heading("Status", text="Status")
        
        self.device_tree.column("ID", width=50)
        self.device_tree.column("Name", width=150)
        self.device_tree.column("IP", width=120)
        self.device_tree.column("Port", width=70)
        self.device_tree.column("Status", width=100)
        
        self.device_tree.pack(side="left", fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(device_list, orient="vertical", command=self.device_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        
        # Device Actions
        action_frame = ttk.Frame(self.device_tab)
        action_frame.pack(pady=5)
        
        self.connect_btn = ttk.Button(action_frame, text="Connect to Device", command=self.connect_device)
        self.connect_btn.pack(side="left", padx=5)
        
        self.disconnect_btn = ttk.Button(action_frame, text="Disconnect", command=self.disconnect_device, state='disabled')
        self.disconnect_btn.pack(side="left", padx=5)
        
        self.fetch_btn = ttk.Button(action_frame, text="Fetch Users", command=self.fetch_users, state='disabled')
        self.fetch_btn.pack(side="left", padx=5)
        
        # Status Bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief='sunken')
        self.status_bar.pack(side='bottom', fill='x')
    
    def create_user_ui(self):

        # User Form (Buttons created first)
        user_form = ttk.LabelFrame(self.user_tab, text="Add User")
        user_form.pack(pady=10, padx=10, fill="x")
        self.user_uid = tk.StringVar()
        self.user_name = tk.StringVar()
        self.user_password = tk.StringVar()
        self.user_group = tk.StringVar()
        self.user_id = tk.StringVar()
        

        # Input fields and buttons
        ttk.Label(user_form, text="UID").grid(row=0, column=0, padx=5, pady=2)
        ttk.Entry(user_form, textvariable=self.user_uid).grid(row=0, column=1, padx=5, pady=2)
        ttk.Label(user_form, text="Name").grid(row=0, column=2, padx=5, pady=2)
        ttk.Entry(user_form, textvariable=self.user_name).grid(row=0, column=3, padx=5, pady=2)
        ttk.Label(user_form, text="Password").grid(row=1, column=0, padx=5, pady=2)
        ttk.Entry(user_form, textvariable=self.user_password).grid(row=1, column=1, padx=5, pady=2)
        ttk.Label(user_form, text="Group ID").grid(row=1, column=2, padx=5, pady=2)
        ttk.Entry(user_form, textvariable=self.user_group).grid(row=1, column=3, padx=5, pady=2)
        ttk.Label(user_form, text="User ID").grid(row=2, column=0, padx=5, pady=2)
        ttk.Entry(user_form, textvariable=self.user_id).grid(row=2, column=1, padx=5, pady=2)


        
        # Buttons (Created Before Binding Event)
        self.save_user_btn = ttk.Button(user_form, text="Save User", command=self.save_user)
        self.save_user_btn.grid(row=3, column=3, padx=5, pady=5)
        self.update_user_btn = ttk.Button(user_form, text="Update User", command=self.update_user, state='disabled')
        self.update_user_btn.grid(row=3, column=2, padx=5, pady=5)
        self.delete_user_btn = ttk.Button(user_form, text="Delete User", command=self.delete_user, state='disabled')
        self.delete_user_btn.grid(row=3, column=1, padx=5, pady=5)
        
        # User List
        user_list = ttk.LabelFrame(self.user_tab, text="Registered Users")
        user_list.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.user_tree = ttk.Treeview(user_list, columns=("ID", "UID", "Name", "Group", "User ID"), show='headings')
        self.user_tree.heading("ID", text="DB ID")
        self.user_tree.heading("UID", text="UID")
        self.user_tree.heading("Name", text="Name")
        self.user_tree.heading("Group", text="Group ID")
        self.user_tree.heading("User ID", text="User ID")
        
        self.user_tree.column("ID", width=50)
        self.user_tree.column("UID", width=80)
        self.user_tree.column("Name", width=150)
        self.user_tree.column("Group", width=100)
        self.user_tree.column("User ID", width=100)
        
        self.user_tree.pack(side="left", fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(user_list, orient="vertical", command=self.user_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.user_tree.configure(yscrollcommand=scrollbar.set)

        # Bind Treeview Selection
        self.user_tree.bind("<<TreeviewSelect>>", self.load_user_into_form)
        
        # Device Access Section
        access_frame = ttk.LabelFrame(self.user_tab, text="Device Access Control")
        access_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Label(access_frame, text="Select User:").pack(side="left", padx=5)
        self.user_listbox = tk.Listbox(access_frame, selectmode='multiple', height=5)
        self.user_listbox.pack(side="left", padx=5)
        
        ttk.Label(access_frame, text="Grant Access to Device:").pack(side="left", padx=5)
        self.device_selector = ttk.Combobox(access_frame, state="readonly")
        self.device_selector.pack(side="left", padx=5)
        
        ttk.Button(access_frame, text="Set Access", command=self.set_access).pack(side="left", padx=5)
        
        # Access Table
        access_table = ttk.LabelFrame(self.user_tab, text="User Access Details")
        access_table.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.access_tree = ttk.Treeview(access_table, 
                                       columns=("User", "Device", "Expiration", "Revoke"),
                                       show='headings')
        self.access_tree.heading("User", text="User")
        self.access_tree.heading("Device", text="Device")
        self.access_tree.heading("Expiration", text="Expiration Date")
        self.access_tree.heading("Revoke", text="Actions")
        
        self.access_tree.column("User", width=150)
        self.access_tree.column("Device", width=150)
        self.access_tree.column("Expiration", width=150)
        self.access_tree.column("Revoke", width=100)
        
        self.access_tree.pack(side="left", fill="both", expand=True)
        
        scrollbar2 = ttk.Scrollbar(access_table, orient="vertical", command=self.access_tree.yview)
        scrollbar2.pack(side="right", fill="y")
        self.access_tree.configure(yscrollcommand=scrollbar2.set)
        
        self.load_access_details()
    
    # Database Helper Functions
    def refresh_selectors(self):
        c = self.conn.cursor()
        
        # Refresh user selector
        c.execute("SELECT id, name FROM users")
        users = c.fetchall()
        self.user_selector['values'] = [f"{u[0]} - {u[1]}" for u in users]
        
        # Refresh device selector
        c.execute("SELECT id, name FROM devices")
        devices = c.fetchall()
        self.device_selector['values'] = [f"{d[0]} - {d[1]}" for d in devices]
    
    def load_devices(self):
        self.device_tree.delete(*self.device_tree.get_children())
        c = self.conn.cursor()
        c.execute("SELECT id, name, ip, port FROM devices")
        for row in c.fetchall():
            self.device_tree.insert('', 'end', values=(*row, "Offline"))
        self.refresh_selectors()
    
    def load_users(self):
        self.user_tree.delete(*self.user_tree.get_children())
        c = self.conn.cursor()
        c.execute("SELECT id, uid, name, group_id, user_id FROM users")
        for row in c.fetchall():
            self.user_tree.insert('', 'end', values=row)
        self.refresh_selectors()




    # Update refresh_selectors() to populate listbox:
    def refresh_selectors(self):
        c = self.conn.cursor()
        
        # Refresh user list
        c.execute("SELECT id, name FROM users")
        users = c.fetchall()
        self.user_listbox.delete(0, tk.END)
        for u in users:
            self.user_listbox.insert(tk.END, f"{u[0]} - {u[1]}")
        
        # Refresh device selector
        c.execute("SELECT id, name FROM devices")
        devices = c.fetchall()
        self.device_selector['values'] = [f"{d[0]} - {d[1]}" for d in devices]
    


    def load_access_details(self):
        self.access_tree.delete(*self.access_tree.get_children())
        c = self.conn.cursor()
        
        query = '''SELECT u.name, d.name, a.expiration_date, a.id, u.id, d.id
                FROM device_access a
                JOIN users u ON a.user_id = u.id
                JOIN devices d ON a.device_id = d.id'''
        
        c.execute(query)
        
        now = datetime.now()
        
        for row in c.fetchall():
            user, device, expiration_data, access_id, user_id, device_id = row
            
            # Parse expiration
            try:
                if isinstance(expiration_data, datetime):
                    expiration = expiration_data
                elif isinstance(expiration_data, str):
                    try:
                        expiration = datetime.fromisoformat(expiration_data)
                    except ValueError:
                        expiration = datetime.strptime(expiration_data, "%Y-%m-%d")
                else:
                    expiration = now
            except Exception as e:
                logging.warning(f"Failed to parse expiration date: {e}")
                expiration = now
            
            # Calculate time remaining
            delta = expiration - now
            total_seconds = int(delta.total_seconds())
            
            if total_seconds < 0:
                status = "Expired"
            else:
                days, remainder = divmod(total_seconds, 86400)
                hours, remainder = divmod(remainder, 3600)
                minutes, _ = divmod(remainder, 60)
                
                if days > 0:
                    status = f"{days}d {hours}h {minutes}m"
                elif hours > 0:
                    status = f"{hours}h {minutes}m"
                else:
                    status = f"{minutes}m"
            
            self.access_tree.insert('', 'end', values=(user, device, expiration.strftime("%Y-%m-%d %H:%M"), status, user_id, device_id))
    

    
    def save_device(self):
        try:
            name = self.device_name.get().strip()
            ip = self.device_ip.get().strip()
            password = self.device_password.get().strip()
            description = self.device_desc.get().strip()

            try:
                port = int(self.device_port.get())
                if port < 1 or port > 65535:
                    raise ValueError("Port must be between 1 and 65535")
            except (ValueError, tk.TclError):
                raise ValueError("Port must be a valid number between 1 and 65535")

            c = self.conn.cursor()
            c.execute('''
                INSERT INTO devices (name, ip, port, password, description)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, ip, port, password, description))
            self.conn.commit()

            self.load_devices()
            self.clear_device_form()
            messagebox.showinfo("Success", "Device added successfully!")

        except ValueError as ve:
            logging.warning(f"Invalid device input: {ve}")
            messagebox.showerror("Input Error", str(ve))
        except sqlite3.IntegrityError:
            logging.warning(f"Duplicate IP attempted: {self.device_ip.get()}")
            messagebox.showerror("Error", "Device with this IP already exists!")
        except Exception as e:
            logging.error(f"Failed to save device: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to save device: {e}")
    
    def connect_device(self):
        selected = self.device_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a device")
            return

        item = self.device_tree.item(selected[0])
        device_id = item['values'][0]

        try:
            c = self.conn.cursor()
            c.execute("SELECT ip, port, password FROM devices WHERE id=?", (device_id,))
            result = c.fetchone()

            if not result:
                messagebox.showerror("Error", "Device not found in database")
                logging.error(f"Device ID {device_id} not found in database")
                return

            ip, port, password = result

            # Log raw values for debugging
            logging.debug(f"Raw device data - IP: {ip}, Port: {port}, Password: {password}")

            # Handle invalid port values
            try:
                if port is None or str(port).strip() == '':
                    raise ValueError("Port is missing or empty")
                port = int(port)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port out of range: {port}")
            except (ValueError, TypeError) as ve:
                logging.warning(f"Invalid port value: {ve}")
                port = 4370
                messagebox.showwarning(
                    "Invalid Port",
                    f"Device port was invalid ({ve}) and has been set to default (4370). Please update the device settings."
                )

            # Sanitize password: convert to int, default to 0 if empty
            try:
                password = int(password) if password not in (None, '') else 0
            except (ValueError, TypeError):
                password = 0
                logging.warning("Invalid password format, defaulting to 0")

            # Now safely connect
            logging.info(f"Connecting to device: IP={ip}, Port={port}, Password={password}")
            self.zk = ZK(ip, port=port, timeout=5, password=password)
            self.current_device_conn = self.zk.connect()
            self.current_device_conn.disable_device()

            # UI updates
            self.device_tree.item(selected[0], values=(*item['values'][0:4], "Online"))
            self.connect_btn.config(state='disabled')
            self.disconnect_btn.config(state='normal')
            self.fetch_btn.config(state='normal')
            self.update_status(f"Connected to device {ip}")
            logging.info("Connection successful")

        except Exception as e:
            error_msg = f"Failed to connect: {e}"
            logging.error(error_msg, exc_info=True)
            messagebox.showerror("Connection Error", error_msg)
            self.update_status("Connection failed")
    
    def disconnect_device(self):
        if self.current_device_conn:
            self.current_device_conn.enable_device()
            self.current_device_conn.disconnect()
            self.current_device_conn = None
            
            # Update UI
            self.connect_btn.config(state='normal')
            self.disconnect_btn.config(state='disabled')
            self.fetch_btn.config(state='disabled')
            
            # Update device status in tree
            for item in self.device_tree.get_children():
                values = self.device_tree.item(item)['values']
                if len(values) > 4:
                    self.device_tree.item(item, values=(*values[:4], "Offline"))
            self.update_status("Disconnected from device")
    
    def fetch_users(self):
        try:
            if not self.current_device_conn:
                raise Exception("Not connected to any device")
                
            users = self.current_device_conn.get_users()
            c = self.conn.cursor()
            
            for user in users:
                # Check if user exists in database
                c.execute("SELECT id FROM users WHERE uid=?", (user.uid,))
                if not c.fetchone():
                    # Add new user if not exists
                    c.execute('''INSERT INTO users (uid, name, password, group_id, user_id, created_at)
                                 VALUES (?, ?, ?, ?, ?, ?)''',
                             (user.uid, user.name, user.password, user.group_id,
                              user.user_id, datetime.now()))
                    
                # Ensure access entry exists for this device
                c.execute("SELECT id FROM device_access WHERE user_id=(SELECT id FROM users WHERE uid=?) AND device_id=?",
                         (user.uid, self.get_current_device_id()))
                if not c.fetchone():
                    # Set default expiration (1 year)
                    expiration = datetime.now() + timedelta(days=365)
                    c.execute('''INSERT INTO device_access (user_id, device_id, expiration_date)
                                 VALUES ((SELECT id FROM users WHERE uid=?), ?, ?)''',
                             (user.uid, self.get_current_device_id(), expiration))
            
            self.conn.commit()
            self.load_users()
            self.load_access_details()
            messagebox.showinfo("Success", f"Fetched {len(users)} users from device")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch users: {e}")
    
    def get_current_device_id(self):
        selected = self.device_tree.selection()
        if selected:
            return self.device_tree.item(selected[0])['values'][0]
        return None
    
    # User Management Functions
    def save_user(self):
        created_at = datetime.now().isoformat()
        try:
            c = self.conn.cursor()
            c.execute('''INSERT INTO users (uid, name, password, group_id, user_id, created_at)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     (self.user_uid.get(), self.user_name.get(),
                      self.user_password.get(), self.user_group.get(),
                      self.user_id.get(), created_at))
            self.conn.commit()
            self.load_users()
            self.clear_user_form()
            messagebox.showinfo("Success", "User saved successfully!")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "User with this UID already exists!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save user: {e}")
    
    def clear_user_form(self):
        self.user_uid.set("")
        self.user_name.set("")
        self.user_password.set("")
        self.user_group.set("")
        self.user_id.set("")
        self.current_user_id = None
        self.update_user_btn.config(state='disabled')


    #Load Selected User into Form
    def load_user_into_form(self, event):
        selected = self.user_tree.selection()
        if not selected:
            return
        item = self.user_tree.item(selected[0])
        user_db_id = item['values'][0]  # First column is DB ID
        c = self.conn.cursor()
        c.execute("SELECT uid, name, password, group_id, user_id FROM users WHERE id=?", (user_db_id,))
        user_data = c.fetchone()
        if user_data:
            self.user_uid.set(user_data[0])
            self.user_name.set(user_data[1])
            self.user_password.set(user_data[2])
            self.user_group.set(user_data[3])
            self.user_id.set(user_data[4])
            self.current_user_id = user_db_id
            self.update_user_btn.config(state='normal')
            if self.delete_user_btn:
                self.delete_user_btn.config(state='normal')
        



    # Update User in Database
    def update_user(self):
        if not self.current_user_id:
            messagebox.showerror("Error", "No user selected for update")
            return
        try:
            c = self.conn.cursor()
            c.execute('''UPDATE users SET
                        uid=?, name=?, password=?, group_id=?, user_id=?
                        WHERE id=?''',
                    (self.user_uid.get(), self.user_name.get(),
                    self.user_password.get(), self.user_group.get(),
                    self.user_id.get(), self.current_user_id))
            self.conn.commit()
            self.load_users()
            self.clear_user_form()
            messagebox.showinfo("Success", "User updated successfully!")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "User with this UID already exists!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update user: {e}")


    def delete_user(self):
        if not self.current_user_id:
            messagebox.showerror("Error", "No user selected for deletion")
            return
            
        confirm = messagebox.askyesno(
            "Confirm Deletion",
            "Are you sure you want to delete this user? This action cannot be undone."
        )
        
        if not confirm:
            return
        
        try:
            c = self.conn.cursor()
            # Delete from device_access first due to foreign key constraint
            c.execute("DELETE FROM device_access WHERE user_id=?", (self.current_user_id,))
            # Then delete the user
            c.execute("DELETE FROM users WHERE id=?", (self.current_user_id,))
            self.conn.commit()
            
            self.load_users()
            self.clear_user_form()
            messagebox.showinfo("Success", "User deleted successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete user: {e}")
            logging.error(f"Error deleting user: {e}")




    # Access Control Functions
    def set_access(self):
        selected_users = self.user_listbox.curselection()
        device_sel = self.device_selector.get()
        
        if not selected_users or not device_sel:
            messagebox.showwarning("Warning", "Please select at least one user and a device")
            return

        try:
            device_id = int(device_sel.split(" - ")[0])
            c = self.conn.cursor()

            # Ask for expiration date
            expiration = ask_datetime(self.root, "Expiration Date & Time")
            if not expiration:
                return  # User canceled

            expiration_date = expiration
            expiration_str = expiration.isoformat()

            # Process each selected user
            for idx in selected_users:
                user_line = self.user_listbox.get(idx)
                user_id = int(user_line.split(" - ")[0])

                # Fetch user data
                user_data = c.execute("SELECT uid, name, password, group_id, user_id FROM users WHERE id=?", (user_id,)).fetchone()
                if not user_data:
                    logging.warning(f"User ID {user_id} not found in database")
                    continue

                db_uid, db_name, db_password, db_group_id, db_user_id = user_data

                # Sanitize user fields — ALL MUST BE STRINGS
                try:
                    # Convert UID to string
                    uid = str(db_uid)
                    # Name defaults to empty string
                    name = db_name or ""
                    # Password defaults to empty string
                    password = db_password or ""
                    # Group ID defaults to '0' if empty or invalid
                    group_id = db_group_id if db_group_id not in (None, '') else '0'
                    if not isinstance(group_id, str):
                        group_id = str(group_id)
                    # User ID defaults to '0'
                    user_id_str = db_user_id or '0'
                    if not isinstance(user_id_str, str):
                        user_id_str = str(user_id_str)

                except Exception as ve:
                    logging.error(f"Failed to sanitize user data: {ve}")
                    messagebox.showerror("Data Error", f"Invalid user data: {ve}")
                    continue  # Skip this user

                # Fetch device info
                dev_info = c.execute("SELECT ip, port, password FROM devices WHERE id=?", (device_id,)).fetchone()
                if not dev_info:
                    raise ValueError(f"Device ID {device_id} not found in database")

                ip, db_port, db_dev_password = dev_info

                # Sanitize device port
                try:
                    port = int(db_port) if db_port not in (None, '') else 4370
                    if not (1 <= port <= 65535):
                        port = 4370
                        logging.warning(f"Port {db_port} out of range, defaulting to 4370")
                except (ValueError, TypeError):
                    port = 4370
                    logging.warning("Invalid port format, defaulting to 4370")

                # Sanitize device password
                try:
                    dev_password = int(db_dev_password) if db_dev_password not in (None, '') else 0
                    dev_password = str(dev_password)
                except (ValueError, TypeError):
                    dev_password = '0'
                    logging.warning("Invalid device password format, defaulting to '0'")

                # Check if access exists
                c.execute("SELECT id FROM device_access WHERE user_id=? AND device_id=?", 
                        (user_id, device_id))
                existing = c.fetchone()

                if existing:
                    c.execute("UPDATE device_access SET expiration_date=? WHERE id=?",
                            (expiration_str, existing[0]))
                else:
                    c.execute("INSERT INTO device_access (user_id, device_id, expiration_date) VALUES (?, ?, ?)",
                            (user_id, device_id, expiration_str))
            
            self.conn.commit()

            # Connect to device if online
            is_online = self.check_device_status(ip, port)

            if is_online:
                try:
                    zk = ZK(ip, port=port, timeout=5, password=dev_password)
                    conn = zk.connect()
                    conn.disable_device()

                    # Create all users on device
                    for idx in selected_users:
                        user_line = self.user_listbox.get(idx)
                        user_id = int(user_line.split(" - ")[0])
                        
                        user_data = c.execute("SELECT uid, name, password, group_id, user_id FROM users WHERE id=?", (user_id,)).fetchone()
                        if not user_data:
                            continue

                        db_uid, db_name, db_password, db_group_id, db_user_id = user_data

                        # Re-sanitize for device
                        try:
                            uid = str(db_uid)
                            name = db_name or ""
                            password = db_password or ""
                            group_id = db_group_id if db_group_id not in (None, '') else '0'
                            if not isinstance(group_id, str):
                                group_id = str(group_id)
                            user_id_str = db_user_id or '0'
                            if not isinstance(user_id_str, str):
                                user_id_str = str(user_id_str)
                        except Exception as ve:
                            logging.error(f"Failed to sanitize user data for device: {ve}")
                            continue

                        # Create user on device
                        conn.set_user(
                            uid=int(uid),
                            name=name,
                            privilege=const.USER_DEFAULT,
                            password=password,
                            group_id=group_id,
                            user_id=user_id_str
                        )

                    conn.enable_device()
                    conn.disconnect()
                    logging.info(f"Successfully added {len(selected_users)} users to device {ip}")
                except Exception as e:
                    logging.error(f"Failed to add users to device: {e}", exc_info=True)
                    messagebox.showerror("Device Error", f"Could not add users to device: {e}")

            self.load_access_details()
            self.refresh_selectors()  # Update combo boxes/listboxes
            messagebox.showinfo("Success", f"Access updated for {len(selected_users)} users!")

        except Exception as e:
            logging.error(f"Failed to update access: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to update access: {e}")
    

    def start_expiration_checker(self):
        """Start background task to check for expired access"""
        self.check_expired_access()  # Run once on startup
        # Check every hour (3600000 ms)
        self.root.after(3600000, self.start_expiration_checker)

    def check_expired_access(self):
        """Check and handle expired access entries"""
        try:
            c = self.conn.cursor()
            now = datetime.now()
            
            # Get expired accesses
            c.execute("""
                SELECT da.id, da.user_id, da.device_id, u.uid, d.ip, d.port, d.password
                FROM device_access da
                JOIN users u ON da.user_id = u.id
                JOIN devices d ON da.device_id = d.id
                WHERE da.expiration_date <= ?
            """, (now,))
            
            expired_entries = c.fetchall()
            logging.info(f"Found {len(expired_entries)} expired access entries")
            
            for entry in expired_entries:
                access_id, user_id, device_id, uid, ip, port, dev_password = entry
                
                # Try to remove user from device if online
                if self.check_device_status(ip, port):
                    try:
                        # Sanitize inputs
                        port = int(port) if port else 4370
                        dev_password = dev_password if dev_password not in (None, '') else '0'
                        dev_password = str(dev_password)
                        
                        # Connect to device
                        zk = ZK(ip, port=port, timeout=5, password=dev_password)
                        conn = zk.connect()
                        conn.disable_device()
                        
                        # Remove user
                        conn.delete_user(uid=int(uid))
                        conn.enable_device()
                        conn.disconnect()
                        
                        logging.info(f"Removed expired user {uid} from device {ip}")
                    except Exception as e:
                        logging.error(f"Failed to remove user {uid} from device {ip}: {e}")
                
                # Remove access entry from database
                try:
                    c.execute("DELETE FROM device_access WHERE id=?", (access_id,))
                    self.conn.commit()
                    logging.info(f"Deleted access entry ID {access_id}")
                except Exception as e:
                    logging.error(f"Database error deleting access ID {access_id}: {e}")
            
            # Update UI
            self.load_access_details()
            
        except Exception as e:
            logging.error(f"Error checking expired access: {e}")
        

    def check_device_status(self, ip, port):
        try:
            zk = ZK(ip, port=port, timeout=2)
            conn = zk.connect()
            conn.disconnect()
            return True
        except:
            return False
    
    def update_status(self, message):
        self.status_bar.config(text=message)
    
    def clear_device_form(self):
        self.device_name.set("")
        self.device_ip.set("")
        self.device_port.set(4370)
        self.device_password.set("")
        self.device_desc.set("")

if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = DeviceManager(root)
    root.mainloop()