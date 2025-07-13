# zk_gui

**How to Set Up and Use the zk Teco Device Management GUI Application**

This application allows you to manage multiple zk Teco devices simultaneously and efficiently control gym access by granting timed access permissions. It stores all user information locally for convenient future management.

**Follow these steps to get started:**

1. **Create a Python virtual environment** to isolate the app’s dependencies and avoid conflicts with other projects.  
   For example, run:  
   ```bash
   python -m venv zk_env
   ```
   Then activate the environment:  
   - On Windows:  
     ```bash
     zk_env\Scripts\activate
     ```
   - On macOS/Linux:  
     ```bash
     source zk_env/bin/activate
     ```

2. **Install the required Python packages** listed in the `requirements.txt` file by running:  
   ```bash
   pip install -r requirements.txt
   ```
   This ensures all necessary libraries are installed with compatible versions.

3. **Launch the GUI application** by executing:  
   ```bash
   python gui_zk.py
   ```
   The app will open a user-friendly interface for managing your zk Teco devices.

4. **Use the app to manage device access:**  
   - Add and configure multiple devices simultaneously.  
   - Grant user access with customizable expiration dates and times.  
   - Manage gym memberships and monitor access logs.  
   - All user data is securely stored in a local database for easy retrieval and management.

**Why use this app?**  
It simplifies device management, automates access control with expiration, and keeps your user data organized locally, making gym management seamless and efficient.

