# LordsBloatRemover

**A simple, comprehensible, and customizable anti‑bloatware PowerShell script for Windows 10 & 11.**

---

## 🚀 Table of Contents

- [Features](#features)  
- [Requirements](#requirements)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Configuration](#configuration)  
- [Customization](#customization)  
- [Contributing](#contributing)  
- [Support](#support)  
- [License](#license)  

---

## Features

- 🧹 Automatically removes unwanted OEM and preinstalled apps  
- ✅ Works on both Windows 10 and Windows 11  
- 🛠️ Clear architecture—easy to read and modify  
- 🔄 Fully customizable list of apps you *can* remove  
- 🔁 Quick reinstallation of removed apps if needed  

---

## Requirements

- **Operating System:** Windows 10 (v1809+) or Windows 11  
- **Permissions:** Must run PowerShell as **Administrator**  
- **PowerShell Version:** v5+ (comes with supported Windows versions)  

---

## Installation

1. Clone the repository:
    ```powershell
   git clone https://github.com/4G0NYY/LordsBloatRemover.git
   cd LordsBloatRemover
    ```

2. Verify script permissions:

   ```powershell
   Get-ExecutionPolicy
   ```

   If restricted, temporarily allow execution:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```

---

## Usage

Run the script in elevated PowerShell:

```powershell
.\main.ps1
```

You'll be greeted with a list of detected bloatware apps. You can choose:

1. **Remove all** found apps
2. **Interactively choose** which to remove
3. **Skip removal**

The script logs each step to the console.

---

## Configuration

You can customize which apps to remove:

1. Open `main.ps1` in a text editor
2. Locate the `AppsToRemove` array
3. Add or remove app package names (e.g., `Microsoft.XboxApp`, `Microsoft.YourPhone`)

Example:

```powershell
$AppsToRemove = @(
    "Microsoft.XboxApp",
    "Microsoft.GetHelp",
    "Microsoft.YourPhone"
)
```

---

## Customization

Advanced users can:

* 🗂️ Add new app groups or categories
* ✨ Filter apps by publisher, version, permissions
* 🔄 Automate script execution via Task Scheduler
* ♻️ Integrate with Windows deployment images

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repo
2. Create a feature or bugfix branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add awesome feature'`)
4. Push to your branch (`git push origin feature/my-feature`)
5. Open a Pull Request detailing your improvements

Please ensure your code follows the existing style and includes comments.

---

## Support

If you'd like to report issues or suggest enhancements:

* Use the **Issues** tab on this repo
* Or contact \[[service@agony.ch](mailto:service@agony.ch)]

---

## License

This project is released under the **MIT License**. See [LICENSE](./LICENSE) for details.

---

## 🙏 Acknowledgments

* Inspired by the need for decluttered Windows installs
* Thanks to the PowerShell community and Microsoft's documentation
* Script name homage: *My old Nickname* + *bloat remover*

---

**Enjoy a cleaner, leaner Windows experience!**