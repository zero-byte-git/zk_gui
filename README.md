# ⚡ ZKTeco GUI

<div align="center">

**A simple GUI for interacting ZKTeco Device with a ZeroMQ-based system.**

</div>

## 📖 Overview

`ZKTeco GUI` is a Python-based graphical user interface (GUI) designed to simplify interaction with applications utilizing the ZeroMQ messaging library.  It provides a user-friendly way to send and receive messages, making it ideal for testing and monitoring ZeroMQ-based systems.  The target audience includes developers and system administrators working with ZeroMQ.  This tool streamlines the process of interacting with a ZeroMQ system without needing to write custom scripts or use command-line tools.


## ✨ Features

- Simple and intuitive graphical interface for adding and configuring multiple devices simultaneously.  
- Clear visual representation of message flow.Grant user access with customizable expiration dates and times.  
- Manage gym memberships and monitor access logs.  
- All user data is securely stored in a local database for easy retrieval and management.


## 🛠️ Tech Stack

- **Language:** Python
- **GUI Framework:**  Tkinter
- **GUI Framework:** SQLite


## 🚀 Quick Start

### Prerequisites

- Python 3.11
- `requirements.txt` 

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/zero-byte-git/zk_gui.git
   cd zk_gui
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the GUI:**
   ```bash
   python gui_zk.py
   ```


## 📁 Project Structure

```
zk_gui/
├── README.md
├── gui_zk.py       # Main GUI application script
└── requirements.txt # Project dependencies
```

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.  A more detailed contributing guide will be added in the future.
