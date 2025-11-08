# MCA Web Scanner

**সুপার-শর্ট বর্ণনা:**  
MCA Web Scanner হলো একটি passive ওয়েব স্ক্যানার (Termux-friendly) — এটি সাইটের ফর্ম, লিংক, হেডার, কুকি ইত্যাদি বিশ্লেষণ করে সম্ভাব্য সমস্যার (XSS, SQLi, SSRF, Clickjacking, TLS mixed-content, directory listing) হিউরিস্টিক ড্রিভেন রিপোর্ট তৈরি করে। **WARNING:** কেবল আপনার নিজস্ব বা অনুমোদিত টার্গেট স্ক্যান করুন।

---

## ফিচারসমূহ
- Passive crawling (ফর্ম, লিঙ্ক, হেডার, কুকি সংগ্রহ)
- সহজ-সুজুগ terminal আউটপুট (colored & structured)
- HTML ও JSON রিপোর্ট জেনারেট করা যায়
- হিউরিস্টিক ডিটেকশন: XSS, SQLi, SSRF, Clickjacking, directory listing, ইত্যাদি
- Termux-ভিত্তিক ব্যবহার-দূস্তরদের কথা মাথায় রেখে নির্মিত

---

## প্রয়োজনীয়তা (Dependencies)
Python 3.8+ এবং নিচের প্যাকেজগুলো ইনস্টল থাকা উচিত:
- `aiohttp`
- `beautifulsoup4` (bs4)
- `jinja2`
- `colorama`
- `tqdm`
- (ঐচ্ছিক) `rich` — উন্নত টার্মিনাল আউটপুটের জন্য

Termux এ একবারে ইনস্টল করার উদাহরণ:
```bash
pkg update && pkg upgrade -y
pkg install python -y
pip install aiohttp beautifulsoup4 jinja2 colorama tqdm rich
```

---

## ব্যবহার (Usage)
**সাধারণভাবে CLI থেকে চালানো:**
```bash
python MCA_Web_Scanner.py -t https://example.com
```

**Quick (interactive) mode:**
```bash
python MCA_Web_Scanner.py
# তারপর Prompt এ Target URL পেস্ট করো
```

**রিপোর্ট জেনারেট করা (HTML / JSON):**
```bash
python MCA_Web_Scanner.py -t https://example.com --output report.html --json report.json --assume-yes
```

**বাইল্ড-ইন হেল্প:**
```bash
python MCA_Web_Scanner.py -h
```

---

## CLI Flags (সংক্ষিপ্ত)
- `-t, --target` : টার্গেট URL
- `-m, --max-pages` : সর্বোচ্চ পেজ ক্রল (ডিফল্ট 30)
- `-r, --rate` : requests per second (ডিফল্ট 2.0)
- `--output` : HTML রিপোর্ট ফাইল পথ
- `--json` : JSON রিপোর্ট ফাইল পথ
- `--assume-yes` : permission prompt স্কিপ করে স্বয়ংক্ৰিয় YES ধরা

---

## ডেমো আউটপুট
টুল চালানোর পরে টার্মিনালে সারসংক্ষেপ দেখাবে (High / Medium / Low risks) এবং `INPUT POINT` নামক বাক্সে পাওয়া ইনপুট-পয়েন্টের উদাহরণ দেখাবে। যদি `--output report.html` সেট করা থাকে তাহলে সুন্দর HTML রিপোর্টও পাওয়া যাবে।

---

## KNOWN ISSUES ও Troubleshooting
1. **argparse import error**  
   - পূর্বে রিপোজিটর কোডে `import argparset` ভুল ছিল — এটি `import argparse` হওয়া উচিত। আপডেটেড ফাইলে এই অংশ ঠিক করা আছে।

2. **rich Console / Panel error**  
   - যদি তোমার টার্মিনালে error আসে:  
     ```
     AttributeError: 'Panel' object has no attribute 'soft_wrap'
     ```
     সম্ভাব্য কারণ: কোথাও `Console` নামকে `Panel(...)` দিয়ে ওভাররাইট করা হয়েছে। ঠিক ব্যবহার:
     ```python
     from rich.console import Console
     from rich.panel import Panel

     console = Console()
     console.print(Panel("Hello", title="Info"))
     ```
     নিশ্চিত করো কোথাও `Console = Panel(...)` বা `Console = ...` মত reassignment নেই।

3. **Built-in module attempts to pip install**  
   - স্ক্রিপ্টে `asyncio` এবং `datetime` pip-install করার চেষ্টা করা থাকলে সেটি অপ্রয়োজনীয়; এগুলো Python built-in। রিপোজিটর-এর fixed copy-তে এই অংশ ঠিক করা আছে।

4. **Permission / Legal**  
   - সর্বদা নিশ্চিত করো টার্গেট তোমার নিজস্ব বা অনুমোদিত। অননুমোদিত স্ক্যানিং আইনি সমস্যা তৈরি করতে পারে।

---

## কনট্রিবিউশন।
- বাগ রিপোর্ট / feature request: Issues খুলে দিন।  
- Pull requests গ্রহণ করা হবে — কনফিগারেশন, প্লাগইন সিস্টেম বা reporting উন্নত করার প্রস্তাব歓迎।

---

## License
MIT License — বিস্তারিত LICENSE ফাইলে আছে (অথবা নীচের হিসেবে যোগ করো)।

---

## Contact / Author
Project maintained by the repository owner. যদি README-তে তোমার নাম/ইমেইল/সোশ্যাল যোগ করতে চাও, নিচে বসিয়ে দাও — আমি README আপডেট করে দেবো।
