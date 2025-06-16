# Password Generator and Manager

A secure password generator and management system built with Python.

## Features
- Generate strong passwords with customizable options
- Store passwords securely using encryption
- Manage and retrieve stored passwords
- User-friendly GUI interface

## Setup
1. First, navigate to the project directory:
```bash
cd password_manager
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python password_manager.py
```

## Security
- All passwords are encrypted using Fernet (symmetric encryption)
- Master password is required to access stored passwords
- Passwords are stored locally in an encrypted format

## Project Structure
```
password_manager/
├── password_manager.py  # Main application file
├── requirements.txt     # Python dependencies
└── README.md           # Documentation
```

## Usage
1. When first running the application, you'll be prompted to create a master password
2. Use the "Generate Password" tab to create strong passwords
3. Store your passwords using the "Store Password" tab
4. View and manage your stored passwords in the "View Passwords" tab 