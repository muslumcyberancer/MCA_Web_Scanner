# MCA Web Scanner

**Short description**  
MCA Web Scanner is a passive web scanner (Termux-friendly) that collects forms, links, headers, cookies and applies heuristic checks for common issues (XSS, SQLi, SSRF, clickjacking, mixed-content/TLS issues, directory listing). **WARNING:** Only scan targets you own or have explicit permission to test.

---

## Features
- Passive crawling (collects forms, links, headers, cookies)
- Heuristic detection for: Reflected XSS, SQL Injection, SSRF, Clickjacking, Directory Listing, Insecure TLS, etc.
- Clean terminal output (colored & structured)
- HTML and JSON report generation
- Designed to be usable on Termux / mobile environments

---

## Requirements / Dependencies
- Python 3.8+
- The following Python packages:
  - `aiohttp`
  - `beautifulsoup4` (bs4)
  - `jinja2`
  - `colorama`
  - `tqdm`
  - (optional) `rich` — for enhanced terminal output

Install example (Termux):
```bash
pkg update && pkg upgrade -y
pkg install python -y
pip install aiohttp beautifulsoup4 jinja2 colorama tqdm rich
```

---

## Usage
Run the scanner from the command line:

```bash
python MCA_Web_Scanner.py -t https://example.com
```

Interactive quick mode:

```bash
python MCA_Web_Scanner.py
# Paste the target URL when prompted
```

Generate HTML and JSON reports:

```bash
python MCA_Web_Scanner.py -t https://example.com --output report.html --json report.json --assume-yes
```

View help:

```bash
python MCA_Web_Scanner.py -h
```

---

## CLI Options (short)
- `-t, --target` : Target URL to scan
- `-m, --max-pages` : Maximum pages to crawl (default: 30)
- `-r, --rate` : Requests per second (default: 2.0)
- `--output` : HTML output path (e.g. report.html)
- `--json` : JSON output path (e.g. report.json)
- `--assume-yes` : Skip interactive permission prompt (assume YES)

---

## Output
- Summary printed to the terminal showing High / Medium / Low findings.
- `INPUT POINT` box lists up to two example input points (form actions or query-parameter examples).
- If `--output` or `--json` is used, an HTML and/or JSON report file will be saved.

---

## Known Issues & Troubleshooting
1. **`import argparset` typo**  
   - The original code had a typo (`argparset`). It must be `import argparse`. The fixed copy in this repo replaces that.

2. **`rich` Console / Panel error**  
   - If you see:
     ```
     AttributeError: 'Panel' object has no attribute 'soft_wrap'
     ```
     The likely cause is that `Console` (class) got accidentally reassigned to a `Panel` instance. Use the Console instance correctly:
     ```python
     from rich.console import Console
     from rich.panel import Panel

     console = Console()
     console.print(Panel("Hello", title="Info"))
     ```
     Make sure you do **not** have `Console = Panel(...)` anywhere in the code.

3. **Avoid pip-installing built-in modules**  
   - `asyncio` and `datetime` are built-in Python modules; do not try to `pip install` them. The fixed copy removes attempts to pip-install those modules.

4. **Permissions & Legal**  
   - Only scan hosts you own or have explicit permission to test. Unauthorized scanning can be illegal and may result in penalties.

---

## Contributing
- Issues and pull requests are welcome.
- Suggested improvements: plugin architecture, more robust TLS checks, rate-limiting options, authentication testing workflows.

---

## License
This project is provided under the **MIT License**. Add a `LICENSE` file if you want to include the full license text.

---

## Contact
Maintained by the repository owner. If you want your name, email or social links included in this README, provide them and I will update the file.
