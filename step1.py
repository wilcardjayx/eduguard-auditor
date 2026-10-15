import os, re

def rd(p): return open(p, encoding="utf-8").read()
def wr(p, s): open(p, "w", encoding="utf-8").write(s)

html = rd("ui/index.html")

# keep the old single page for step 2 (outside ui/, not served)
if not os.path.exists("index.old.html"):
    wr("index.old.html", html)

# ---------- base.html ----------
head = html[:html.index("<body>")]
head = re.sub(r"<title>.*?</title>",
    "<title>{% block title %}EduGuard AI - Security Dashboard{% endblock %}</title>", head, count=1, flags=re.S)
MEDIA = """
        @media (max-width: 640px) {
            #global-frame { border-width: 8px; border-radius: 20px; }
            #viewport-content { padding: 8px; }
            #scroll-container { min-height: calc(100vh - 16px); }
        }
    """
head = head.replace("</style>", MEDIA + "</style>", 1)

base = head + """<body>
<div id="global-frame"></div>
<div id="viewport-content">
<div id="scroll-container">

{% set links = [('audit','/audit','Scanner'),('templates','/templates','Template Packs'),('owasp','/owasp','OWASP ASVS'),('engine','/engine','Gemma Engine')] %}
<header class="bg-alabaster text-charcoal-800">
  <nav class="flex justify-between items-center px-4 sm:px-8 py-4 sm:py-6">
    <a href="/" class="flex items-center gap-3">
      <svg width="32" height="32" viewBox="0 0 56 56" fill="none">
        <path d="M28 26L52 38L28 50L4 38Z" fill="#FF6B2B" stroke="#FF6B2B" stroke-width="4" stroke-linejoin="round"/>
        <path d="M28 16L52 28L28 40L4 28Z" fill="#E2FF32" stroke="#E2FF32" stroke-width="4" stroke-linejoin="round"/>
        <path d="M28 6L52 18L28 30L4 18Z" fill="#F4F2ED" stroke="#141414" stroke-width="3" stroke-linejoin="round"/>
        <ellipse cx="28" cy="18" rx="6" ry="3" fill="white" stroke="#141414" stroke-width="1.5"/>
      </svg>
      <span class="font-display font-bold tracking-tight text-xl uppercase">EduGuard</span>
    </a>

    <div class="hidden md:flex items-center gap-6 px-6 py-2 border border-charcoal-800 rounded-full bg-white/50 backdrop-blur-sm text-sm font-medium">
      {% for key, href, label in links %}
      <a href="{{ href }}" class="hover:opacity-70 transition-opacity {{ 'font-bold' if active_page == key else '' }}">{{ label }}</a>
      {% endfor %}
    </div>

    <div class="flex items-center gap-3">
      <div class="hidden lg:flex items-center gap-2 px-4 py-2 bg-charcoal-800 text-alabaster rounded-full text-xs font-mono font-medium">
        <span class="text-acid">●</span> Local Gemma4:E4B — 0KB Cloud Leak
      </div>
      <a href="/audit" class="px-5 py-2 bg-charcoal-800 text-alabaster rounded-full text-sm font-medium hover:bg-charcoal-600 transition-colors">Run Audit ↗</a>
      <button id="menuBtn" aria-label="Menu" class="md:hidden w-10 h-10 flex items-center justify-center border border-charcoal-800 rounded-full">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="4" y1="7" x2="20" y2="7"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="17" x2="20" y2="17"/></svg>
      </button>
    </div>
  </nav>
  <div id="mobileMenu" class="hidden md:hidden flex-col gap-2 px-4 pb-4 text-sm font-medium">
    {% for key, href, label in links %}
    <a href="{{ href }}" class="px-4 py-2.5 border border-charcoal-800 rounded-full {{ 'bg-charcoal-800 text-alabaster' if active_page == key else '' }}">{{ label }}</a>
    {% endfor %}
  </div>
</header>

{% block content %}{% endblock %}

</div>
</div>
<script>
document.getElementById('menuBtn').addEventListener('click', function () {
  var m = document.getElementById('mobileMenu');
  m.classList.toggle('hidden'); m.classList.toggle('flex');
});
</script>
{% block scripts %}{% endblock %}
</body>
</html>
"""
wr("ui/base.html", base)

# ---------- landing page ----------
hero = re.search(r'<section id="hero".*?</section>', html, re.S).group(0)
hero = re.sub(r"(<!-- Navbar -->\s*)?<nav.*?</nav>", "", hero, count=1, flags=re.S)
hero = (hero
    .replace("w-full min-h-[80vh] flex flex-col", "w-full lg:min-h-[80vh] flex flex-col")
    .replace("px-8 lg:px-16 py-12 gap-12 lg:gap-8", "px-4 sm:px-8 lg:px-16 py-8 lg:py-12 gap-8")
    .replace("lg:w-[60%] flex flex-col gap-10", "lg:w-[60%] flex flex-col gap-6 lg:gap-10")
    .replace("text-[48px] lg:text-[68px]", "text-[38px] sm:text-[48px] lg:text-[68px]")
    .replace("rounded-full max-w-3xl", "rounded-3xl sm:rounded-full max-w-3xl")
    .replace('items-center h-[400px] pointer-events-none">',
             'items-center h-[260px] sm:h-[340px] lg:h-[400px] pointer-events-none">')
    .replace('onclick="runScan()"', 'onclick="goAudit()"'))
print("hero ok:", "goAudit" in hero and "hero.mp4" in hero)

card = '''<a href="{href}" class="block bg-charcoal-700 border border-charcoal-500 rounded-[20px] p-6 hover:border-acid transition-colors">
  <span class="font-mono text-xs text-acid">/ {n}</span>
  <h3 class="font-display font-medium text-xl text-white mt-3 mb-2">{title}</h3>
  <p class="font-mono text-sm text-alabaster/60">{text}</p>
</a>'''
steps = ('<section class="bg-charcoal-800 text-alabaster px-4 sm:px-8 lg:px-16 py-12 lg:py-20">'
         '<div class="max-w-[1600px] mx-auto grid grid-cols-1 md:grid-cols-3 gap-4">'
         + card.format(href="/templates", n="01", title="Pick template packs", text="Choose the checks that make up your audit baseline.")
         + card.format(href="/audit", n="02", title="Run the audit", text="Scan a source directory or URL with the local Gemma engine.")
         + card.format(href="/audit", n="03", title="Ship the patch", text="Review findings and copy ready-made remediation patches.")
         + '</div></section>')

script = """<script>
function goAudit() {
  var t = encodeURIComponent(document.getElementById('targetInput').value.trim());
  var m = encodeURIComponent(document.getElementById('scanMode').value);
  location.href = '/audit?target=' + t + '&mode=' + m;
}
document.getElementById('targetInput').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') goAudit();
});
</script>"""
wr("ui/index.html", '{% extends "base.html" %}\n{% block content %}\n' + hero + "\n" + steps
   + '\n{% endblock %}\n{% block scripts %}\n' + script + '\n{% endblock %}\n')

# ---------- owasp / engine ----------
def simple(key, title, text):
    return ('{% extends "base.html" %}\n{% set active_page = "' + key + '" %}\n{% block content %}\n'
            '<section class="bg-charcoal-800 text-alabaster min-h-[70vh] px-4 sm:px-8 lg:px-16 py-12 lg:py-20">'
            '<div class="max-w-[1600px] mx-auto">'
            '<h2 class="font-display font-light text-[36px] md:text-[52px] mb-6">' + title + '</h2>'
            '<p class="font-mono text-sm text-alabaster/70 max-w-2xl">' + text + '</p>'
            '</div></section>\n{% endblock %}\n')
wr("ui/owasp.html", simple("owasp", "OWASP ASVS", "Add your OWASP ASVS mapping and coverage details here."))
wr("ui/engine.html", simple("engine", "Gemma Engine", "Add details about the local Gemma4:E4B engine here."))

# ---------- app.py ----------
src = rd("app.py")
anchor = '    return templates.TemplateResponse("index.html", {"request": request, "packs": packs})\n'
print("anchor found:", anchor in src)
src = src.replace(anchor, anchor + '''
@app.get("/owasp", response_class=HTMLResponse)
async def owasp_page(request: Request):
    return templates.TemplateResponse("owasp.html", {"request": request})

@app.get("/engine", response_class=HTMLResponse)
async def engine_page(request: Request):
    return templates.TemplateResponse("engine.html", {"request": request})
''', 1)
wr("app.py", src)
print("done")
