"""Create the DevPilot academic report using the supplied report's page system."""
from pathlib import Path
import hashlib
import json
from PIL import Image, ImageDraw, ImageFont
from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(r"E:\ageennnnntsss\DevPilot_final")
WORK = ROOT / "report_work"
REFERENCE = Path(r"C:\Users\jaina\Downloads\AcquiSense_Final_Project_Report.docx")
OUTPUT = ROOT / "DevPilot_25_Page_Project_Report.docx"
assert hashlib.sha256(REFERENCE.read_bytes()).hexdigest() == "46e8bc0e967b59abbd7c45cc11557010bf0600dc5ac5184b38101a765cbb5210"

FONT_PATH = r"C:\Windows\Fonts\cambria.ttc"
FONT_BOLD_PATH = r"C:\Windows\Fonts\cambriab.ttf"


def pil_font(size, bold=False):
    return ImageFont.truetype(FONT_BOLD_PATH if bold else FONT_PATH, size)


def diagram():
    im = Image.new("RGB", (2100, 980), "white")
    draw = ImageDraw.Draw(im)
    boxes = [
        (60, 90, 390, 220, "Upload or Git input", "FastAPI ingestion", "#E8F0FA"),
        (500, 90, 830, 220, "CrewAI coordinator", "Run state and routing", "#E8F0FA"),
        (940, 90, 1270, 220, "A2A worker", "AST and vector tools", "#E5F4EF"),
        (1380, 90, 1710, 220, "Static analyzers", "Five language families", "#E5F4EF"),
        (700, 410, 1030, 540, "Gemini review", "Line grounded suggestions", "#FFF0DE"),
        (1130, 410, 1460, 540, "Evaluator", "Ground and verify", "#FFF0DE"),
        (700, 730, 1030, 860, "Sandbox broker", "Disposable test container", "#E5F4EF"),
        (1130, 730, 1460, 860, "Report and patch gate", "Verified exports only", "#E8F0FA"),
    ]
    for x1, y1, x2, y2, title, sub, fill in boxes:
        draw.rounded_rectangle((x1, y1, x2, y2), radius=18, fill=fill, outline="#6B7C93", width=3)
        draw.text((x1 + 20, y1 + 22), title, fill="#1F2937", font=pil_font(30, True))
        draw.text((x1 + 20, y1 + 80), sub, fill="#334155", font=pil_font(24))
    arrows = [((390, 155), (500, 155)), ((830, 155), (940, 155)), ((1270, 155), (1380, 155)),
              ((665, 220), (865, 410)), ((1540, 220), (1295, 410)), ((1030, 475), (1130, 475)),
              ((1295, 540), (865, 730)), ((1030, 795), (1130, 795))]
    for a, b in arrows:
        draw.line((a, b), fill="#334155", width=5)
        dx, dy = b[0] - a[0], b[1] - a[1]
        norm = max((dx * dx + dy * dy) ** 0.5, 1)
        ux, uy = dx / norm, dy / norm
        px, py = -uy, ux
        draw.polygon([b, (b[0] - 20 * ux + 11 * px, b[1] - 20 * uy + 11 * py),
                      (b[0] - 20 * ux - 11 * px, b[1] - 20 * uy - 11 * py)], fill="#334155")
    draw.rounded_rectangle((60, 410, 540, 570), radius=18, fill="#F1F5F9", outline="#94A3B8", width=2)
    draw.text((85, 440), "Redis blackboard", fill="#1F2937", font=pil_font(31, True))
    draw.text((85, 500), "Shared run state", fill="#334155", font=pil_font(25))
    path = WORK / "architecture.png"
    im.save(path)
    return path


def benchmark_chart():
    data = json.loads((ROOT / "benchmark/results/polyglot_50_benchmark_results.json").read_text(encoding="utf-8"))
    rows = [(language, values["TP"], values["TN"]) for language, values in data["per_language"].items()]
    im = Image.new("RGB", (1600, 800), "white")
    d = ImageDraw.Draw(im)
    d.text((80, 50), "Curated benchmark outcomes by language", fill="black", font=pil_font(42, True))
    for i, (name, tp, tn) in enumerate(rows):
        y = 160 + i * 120
        d.text((80, y + 10), name, fill="#1F2937", font=pil_font(30))
        d.rectangle((350, y, 350 + tp * 70, y + 40), fill="#4E8EBB")
        d.rectangle((350 + tp * 70, y, 350 + (tp + tn) * 70, y + 40), fill="#9ACCB5")
        d.text((1120, y + 5), f"{tp} defect / {tn} clean", fill="#334155", font=pil_font(26))
    d.rectangle((80, 720, 110, 750), fill="#4E8EBB")
    d.text((120, 720), "Defect cases detected", fill="#334155", font=pil_font(23))
    d.rectangle((480, 720, 510, 750), fill="#9ACCB5")
    d.text((520, 720), "Clean cases rejected", fill="#334155", font=pil_font(23))
    path = WORK / "benchmark.png"
    im.save(path)
    return path


doc = Document(REFERENCE)
body_el = doc._element.body
for child in list(body_el):
    if child.tag != qn("w:sectPr"):
        body_el.remove(child)
section = doc.sections[0]
section.different_first_page_header_footer = True
section.page_width, section.page_height = Inches(8.5), Inches(11)
section.left_margin = section.right_margin = Inches(1)
section.top_margin, section.bottom_margin = Inches(1), Inches(0.9)
for footer in (section.footer, section.first_page_footer):
    for paragraph in footer.paragraphs:
        paragraph.clear()
footer = section.footer.paragraphs[0]
footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = footer.add_run()
run.font.name, run.font.size = "Cambria", Pt(9)
fld = OxmlElement("w:fldSimple")
fld.set(qn("w:instr"), "PAGE")
run._r.addnext(fld)

styles = doc.styles
for name in ("normal", "Normal"):
    if name in styles:
        st = styles[name]
        st.font.name, st.font.size, st.font.color.rgb = "Cambria", Pt(11), RGBColor(0, 0, 0)
        st.paragraph_format.space_after = Pt(7)
        st.paragraph_format.line_spacing = 1.25
for name, size, before, after in (("Heading 1", 16, 0, 10), ("Heading 2", 13, 12, 6)):
    st = styles[name]
    st.font.name, st.font.size, st.font.bold, st.font.color.rgb = "Cambria", Pt(size), True, RGBColor(0, 0, 0)
    st.paragraph_format.space_before, st.paragraph_format.space_after = Pt(before), Pt(after)
    st.paragraph_format.keep_with_next = True
title_style = styles["Title"]
title_style.font.name, title_style.font.size, title_style.font.bold, title_style.font.color.rgb = "Cambria", Pt(20), True, RGBColor(0, 0, 0)
title_style.paragraph_format.space_after = Pt(10)


def paragraph(text="", *, bold_lead=None, align=WD_ALIGN_PARAGRAPH.JUSTIFY, style="normal"):
    p = doc.add_paragraph(style=style)
    p.alignment = align
    if bold_lead and text.startswith(bold_lead):
        p.add_run(bold_lead).bold = True
        p.add_run(text[len(bold_lead):])
    else:
        p.add_run(text)
    return p


def center(text, size=11, bold=False, before=0, after=5):
    p = paragraph(text, align=WD_ALIGN_PARAGRAPH.CENTER)
    p.paragraph_format.space_before = Pt(before)
    p.paragraph_format.space_after = Pt(after)
    for r in p.runs:
        r.font.name, r.font.size, r.bold = "Cambria", Pt(size), bold
    return p


def chapter(title, new_page=True):
    p = doc.add_paragraph(title, style="Heading 1")
    p.paragraph_format.page_break_before = new_page
    return p


def sub(title):
    return doc.add_paragraph(title, style="Heading 2")


def bullets(items):
    for item in items:
        p = doc.add_paragraph(style="normal")
        p.add_run("•  " + item)
        p.paragraph_format.left_indent = Inches(0.22)
        p.paragraph_format.first_line_indent = Inches(-0.18)
        p.paragraph_format.space_after = Pt(3)


table_counter = 0


def table(caption, headers, rows, widths=None):
    global table_counter
    table_counter += 1
    cp = center(f"Table {table_counter}: {caption}", size=9, before=4, after=5)
    cp.runs[0].italic = True
    t = doc.add_table(rows=1, cols=len(headers))
    t.autofit = False
    t.style = "TableNormal"
    tbl_pr = t._tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        border = OxmlElement(f"w:{edge}")
        border.set(qn("w:val"), "single")
        border.set(qn("w:sz"), "4")
        border.set(qn("w:color"), "B9C1CA")
        borders.append(border)
    tbl_pr.append(borders)
    for i, head in enumerate(headers):
        t.rows[0].cells[i].text = str(head)
    header_props = t.rows[0]._tr.get_or_add_trPr()
    repeat_header = OxmlElement("w:tblHeader")
    repeat_header.set(qn("w:val"), "true")
    header_props.append(repeat_header)
    for row in rows:
        cells = t.add_row().cells
        for i, value in enumerate(row):
            cells[i].text = str(value)
    for row_index, row in enumerate(t.rows):
        for i, cell in enumerate(row.cells):
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            if widths:
                cell.width = Inches(widths[i])
            tcPr = cell._tc.get_or_add_tcPr()
            shade = OxmlElement("w:shd")
            shade.set(qn("w:fill"), "E8EDF3" if row_index == 0 else ("F7F9FC" if row_index % 2 == 0 else "FFFFFF"))
            tcPr.append(shade)
            for p in cell.paragraphs:
                p.paragraph_format.space_after = Pt(1)
                p.paragraph_format.line_spacing = 1.05
                for r in p.runs:
                    r.font.name, r.font.size, r.font.color.rgb = "Cambria", Pt(8.5), RGBColor(0, 0, 0)
                    if row_index == 0:
                        r.bold = True
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return t


figure_counter = 0


def figure(path, caption, width=6.2):
    global figure_counter
    figure_counter += 1
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    p.add_run().add_picture(str(path), width=Inches(width))
    cp = center(f"Figure {figure_counter}: {caption}", size=9, after=7)
    cp.runs[0].italic = True


# Cover
p = doc.add_paragraph(style="Title")
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.paragraph_format.space_before = Pt(28)
p.add_run("Project Report")
center("Agentic AI", 14, True, after=1)
center("DevPilot", 19, True, before=22, after=3)
center("A Multi-Agent Autonomous Code Inspection and Debugging System", 16, True, after=28)
center("Submitted by", 12, after=15)
center("Yashvardhan Singh", 12, True, after=2)
center("Enrolment Number 230770", 10, after=10)
center("Atharv Jain", 12, True, after=2)
center("Enrolment Number 230635", 10, after=35)
center("Department of Computer Science and Engineering", 11, True, after=2)
center("School of Engineering and Technology", 11, True, after=2)
center("BML Munjal University", 11, True, after=10)
center("November 2026", 11)

# Declaration
doc.add_page_break()
center("Declaration by the Candidates", 16, True, before=20, after=20)
paragraph("This report describes the DevPilot project and the implementation and evaluation evidence available as of November 2026. Each candidate should review the final submission, confirm the individual contributions recorded in Section 8, and sign below before submitting it as a personal declaration.")
for name, number in (("Yashvardhan Singh", "230770"), ("Atharv Jain", "230635")):
    center("______________________________", 11, before=30, after=4)
    center(f"{name} ({number}) - Name and signature", 10, after=15)
paragraph("Place: BML Munjal University")
paragraph("Date: ____________________")

# Contents
doc.add_page_break()
center("Contents", 16, True, before=10, after=15)
contents = [
    "1. Introduction", "2. Problem Statement", "3. Literature Review",
    "4. Requirements for the Multi-Agent System", "5. Methodology",
    "6. Technology Stack", "7. Experimental Results",
    "8. Team Responsibility and Self Contribution", "9. Conclusions",
    "References", "Appendix", "Appendix B. Evidence Register",
    "Appendix C. Interface Contracts", "Appendix D. Inspection Walkthrough",
    "Appendix E. Trust Boundaries", "Appendix F. Verification Protocol",
    "Appendix G. Timeout Analysis", "Appendix H. Next Evaluation",
]
contents_pages = [4, 5, 6, 7, 9, 11, 12, 14, 15, 16, 17, 19, 20, 21, 22, 23, 24, 25]
contents_table = doc.add_table(rows=0, cols=2)
for item, page_number in zip(contents, contents_pages):
    cells = contents_table.add_row().cells
    cells[0].text = item
    cells[1].text = str(page_number)
    cells[1].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT
    for cell in cells:
        for p in cell.paragraphs:
            p.paragraph_format.space_after = Pt(4)
center("List of figures and tables", 11, True, before=20, after=7)
paragraph("The report includes an architecture figure, a curated benchmark chart, and numbered tables covering the problem, requirements, design, evaluation and reproduction steps.")

# Chapter 1
chapter("1. Introduction")
paragraph("Modern repositories mix services, web interfaces, data pipelines and native components. A single inspection method rarely covers all of them. Static rules can find recognizable patterns, while model review can identify context-dependent defects but may produce unsupported claims or incorrect replacements. DevPilot combines these methods and records which conclusions are grounded in source and which corrections have been tested.")
paragraph("The system accepts an uploaded file, folder, ZIP archive, local path or Git repository. It maps the project, performs language-aware static and security analysis, requests a model review of the actual source, checks findings against file lines, and prepares a report. A correction is eligible for export only when relevant isolated checks confirm it. A separate debugging workflow uses a coordinator, worker agents, MCP tools, A2A messages and a shared blackboard.")
paragraph("This report describes the implementation found in the repository and the latest available run evidence. The live Docker check confirms the web service, Redis, A2A/MCP analysis and sandbox execution. The Gemini review timed out in that check, so full model-assisted inspection and verified patch export remain unconfirmed for that run.")
paragraph("Report organisation. Section 2 defines the problem and users. Section 3 reviews related approaches. Section 4 translates the problem into requirements. Section 5 explains the workflow and safeguards. Sections 6 and 7 describe the stack and observed results. Sections 8 and 9 record contribution fields and conclusions. The appendix lists reproduction commands and acceptance checks.", bold_lead="Report organisation.")

# Chapter 2
chapter("2. Problem Statement")
sub("2.1 What problem is being addressed")
paragraph("Code review across multiple languages is slow to coordinate and difficult to verify. The project addresses five recurring gaps between a finding displayed in a dashboard and a dependable correction that a developer can examine.")
table("Problem statement items addressed by DevPilot", ["ID", "Problem", "Consequence"], [
    ("PS1", "Different languages need different parsing and rules", "A single-language scanner misses defects."),
    ("PS2", "LLM output can cite absent lines or invent variables", "Reports and patches become unreliable."),
    ("PS3", "Runtime tests can be unavailable or unsafe to execute", "Static findings are mistaken for verified fixes."),
    ("PS4", "Agent state and tool calls can be disconnected", "The dashboard describes a workflow that did not run."),
    ("PS5", "Build and integration status can be confused with inspection success", "Users cannot tell which stage failed."),
], [0.55, 2.65, 3.25])
sub("2.2 Intended users")
paragraph("The main users are developers reviewing an unfamiliar repository, project maintainers triaging security and runtime issues, and evaluators checking whether a multi-agent system completed a real inspection. The output must let them trace every reported issue to a file and line and distinguish a suggested fix from a tested patch.")
sub("2.3 Why a multi-agent design is relevant")
bullets([
    "Specialist analyzers apply language-aware static, security and runtime rules.",
    "A separate model reviewer examines actual source chunks and returns line-grounded suggestions.",
    "An evaluator rejects unsupported citations and records relevant isolated checks.",
    "A shared blackboard and A2A dispatch make worker outcomes visible to the coordinator.",
])
sub("2.4 Objectives and scope")
table("Project objectives", ["ID", "Objective"], [
    ("O1", "Inspect Python, JavaScript, TypeScript, Java and C/C++ source files."),
    ("O2", "Ground each finding in the uploaded project instead of displaying fixture results."),
    ("O3", "Use Gemini for source review when the API is available and show failure status when it is not."),
    ("O4", "Run behavioral verification only in disposable Docker containers."),
    ("O5", "Export or apply only patches with a verified change."),
    ("O6", "Expose agent, tool and service status in a reproducible inspection report."),
], [0.7, 5.75])
paragraph("Scope. The current implementation covers repository inspection and a separate debugging session. A curated benchmark supports regression checks, but it does not prove the absence of defects in arbitrary uploaded projects. Running tests from an uploaded repository depends on a compatible sandbox image and available project dependencies.", bold_lead="Scope.")

# Chapter 3
chapter("3. Literature Review", new_page=False)
paragraph("DevPilot combines ideas from repository benchmarks, reasoning-and-action agents and interoperability protocols. The related work motivates evaluation by executable tests, explicit tool boundaries and observable agent state.")
sub("3.1 Existing approaches")
table("Approaches and limitations relevant to DevPilot", ["Approach", "Contribution", "Remaining gap"], [
    ("Static analysis", "Fast, repeatable pattern and syntax checks", "Can miss context-specific behavior and may over-report."),
    ("Single-prompt LLM review", "Flexible reasoning across unfamiliar code", "Can hallucinate lines, tests or patch behavior."),
    ("SWE-bench", "Evaluates repository-level issue resolution using tests", "A benchmark result is not evidence for an untested upload."),
    ("ReAct", "Interleaves reasoning with tool actions", "The application still needs safe tools and measured outcomes."),
], [1.35, 2.35, 2.75])
sub("3.2 Protocol and framework context")
paragraph("MCP defines a standard way for an application to expose tools and resources to an agent. A2A concerns communication between agents or agent services. DevPilot uses MCP-shaped tool calls for parsing, search and sandbox execution and a JSON-RPC HTTP path for the codebase analyst worker. The upload inspection path and the full debugging session should be evaluated separately because they invoke different portions of the architecture.")
sub("3.3 Gaps identified")
table("Design gaps and the corresponding response", ["Gap", "Project response"], [
    ("G1", "Ground source lines and paths before accepting model findings."),
    ("G2", "Record LLM availability and timeout reasons instead of substituting fixed results."),
    ("G3", "Keep test execution inside a broker-launched, isolated child container."),
    ("G4", "Use Redis to share state across the web and A2A worker containers."),
    ("G5", "Separate curated benchmark metrics from uploaded-project outcomes."),
], [0.7, 5.75])

# Chapter 4
chapter("4. Requirements for the Multi-Agent System", new_page=False)
paragraph("The following requirements map the problem to observable behavior. A feature is counted as complete only when its own execution evidence is available; the presence of code or a configured API key alone is insufficient.")
table("Requirements mapped to the problem statement", ["ID", "Requirement", "Motivation", "Evidence path"], [
    ("R1", "Accept and retain actual uploaded source", "PS1, PS5", "POST /api/upload"),
    ("R2", "Detect file languages and project manifests", "PS1", "Codebase analyst"),
    ("R3", "Run static, security and runtime rules", "PS1", "Inspection coordinator"),
    ("R4", "Call Gemini on source chunks and expose status", "PS2, PS5", "LLM review summary"),
    ("R5", "Reject absent lines and unsafe patches", "PS2", "Evaluator and corrector"),
    ("R6", "Use Redis for cross-process state", "PS4", "Blackboard state"),
    ("R7", "Dispatch analyst work over A2A HTTP", "PS4", "A2A/MCP status"),
    ("R8", "Execute checks in Docker without a host fallback", "PS3", "Sandbox probe and test summary"),
    ("R9", "Gate corrected exports by verification", "PS3, PS5", "Export endpoints"),
], [0.55, 2.8, 0.8, 2.3])
sub("4.1 Agent identification")
table("Agents and responsibilities", ["Component", "Role", "Implementation"], [
    ("Coordinator", "Creates the inspection run and combines findings", "CrewAI coordinator module"),
    ("Codebase analyst", "Discovers files, AST symbols and vector chunks", "A2A worker and MCP tools"),
    ("Static analyzer", "Detects syntax, logic and quality patterns", "Language-aware adapters"),
    ("Security analyzer", "Detects injection, secrets and unsafe calls", "Security analysis module"),
    ("Runtime analyzer", "Identifies likely exceptions and configuration faults", "Runtime analysis module"),
    ("Evaluator and critic", "Grounds findings and records test outcomes", "Evaluator module"),
    ("Patch reviewer", "Reviews candidate diffs in debugging workflow", "CrewAI reviewer module"),
], [1.4, 2.6, 2.45])

# Chapter 5
chapter("5. Methodology")
sub("5.1 System architecture")
paragraph("The web service stages each upload in a project directory and passes its path to the coordinator. The coordinator first discovers files and asks the A2A worker to run MCP AST parsing and vector indexing. Local analyzers then produce candidate findings. Gemini is asked to review bounded chunks of actual source. The evaluator grounds citations, tries to construct a correction and runs a relevant check when one is available. The report is assembled from these observed results.")
figure(diagram(), "Implemented upload inspection and verification path", 6.2)
sub("5.2 Orchestration and agent execution")
paragraph("The upload inspection path calls specialist analyzers in a defined sequence and records elapsed time by stage. The separate debugging session uses A2A dispatch for analyst, debugger, tester and reviewer methods and may backtrack after a failed test. These are related but distinct entry points; the dashboard's architecture walkthrough is a diagram, not a live stage trace.")
table("Execution patterns considered", ["Pattern", "Benefit", "Limitation"], [
    ("Sequential", "Simple to trace and reproduce", "Dependent steps add latency."),
    ("Concurrent source review", "Several source batches can be reviewed together", "Model gateway throughput can become the bottleneck."),
    ("Hierarchical debugging", "Can revisit a failed diagnosis or test", "Needs clear stopping and approval rules."),
], [1.35, 2.45, 2.65])
sub("5.3 Shared state and A2A messaging")
paragraph("The BlackboardStore keeps a run identifier, source path, status and structured artifacts. In Docker Compose, the web and worker processes use Redis, and an upload volume makes staged files visible to both. The coordinator refreshes Redis state after the worker responds before recording the next status. A2A requests use JSON-serializable parameters and an internal authenticated HTTP endpoint.")
sub("5.4 MCP tools")
table("Tool boundaries in the system", ["Tool", "Purpose", "Observed use"], [
    ("AST parser", "Extract symbols, calls and syntax warnings", "A2A analyst path"),
    ("Vector codebase", "Index and search source chunks", "A2A analyst path"),
    ("Tavily search", "Retrieve external technical guidance", "Debugging workflow when configured"),
    ("Docker sandbox", "Run tests in an isolated child container", "Probe passed in live Compose run"),
], [1.55, 2.35, 2.55])
sub("5.5 Model review and grounding")
paragraph("The model reviewer reads source files from disk, numbers lines, splits them into bounded chunks and requests issue records. It accepts a returned issue only when the file exists and the cited line matches the actual source line. Suggested replacement code remains unverified until a relevant patch check passes. A model request failure is reported as an error; it does not silently promote static findings to verified patches.")
sub("5.6 Docker isolation and patch export")
paragraph("The web container sends a bounded archive and a restricted verification command to an internal sandbox broker. The broker launches a disposable child image with no network, a read-only root filesystem, dropped capabilities, resource limits and a temporary filesystem. Python and C++ images are built by Compose. The export APIs refuse to publish a corrected project when the inspection report has no verified patch.")
sub("5.7 Validation design")
paragraph("Validation has three levels: source grounding, syntax and symbol checks on a proposed patch, and an isolated behavioral check when a relevant test exists. The curated 50-scenario benchmark measures detector behavior on known fixtures. The live integration checker separately exercises upload, Redis, A2A/MCP, LLM review and a small real sandbox probe. These tests answer different questions and are reported separately.")

# Chapter 6
chapter("6. Technology Stack")
table("Technology stack", ["Layer", "Technology", "Role"], [
    ("Web/API", "Python 3.12, FastAPI, Uvicorn", "Upload, inspection and report endpoints"),
    ("Agent orchestration", "CrewAI modules and local coordinator", "Run planning and patch review"),
    ("Worker transport", "A2A JSON-RPC over HTTP", "Analyst dispatch across containers"),
    ("Tools", "MCP client/server, AST parser, vector search", "Language and repository context"),
    ("Model", "Gemini via google-genai SDK", "Source review and debugging suggestions"),
    ("State", "Redis and Pydantic models", "Shared run data and typed reports"),
    ("Sandbox", "Docker Desktop, broker, Python/C++ images", "Isolated test execution"),
    ("Frontend", "HTML, CSS and JavaScript dashboard", "Inspection input and evidence display"),
    ("Evidence", "JSON/CSV benchmark artifacts and Compose logs", "Recorded results and diagnostics"),
], [1.35, 2.5, 2.6])
paragraph("The project is packaged through docker/docker-compose.yml. The web service exposes port 8000, while Redis, the worker and broker provide internal services to the inspection path. Source bind mounts allow local code changes to be loaded after a service restart without reinstalling the entire dependency set.")

# Chapter 7
chapter("7. Experimental Results")
sub("7.1 Experimental setup")
paragraph("Two evidence sets are available. The repository contains a 50-scenario curated polyglot detector artifact with 40 labeled defect cases and 10 clean cases. A separate live Compose check on 26 November 2026 built the images, uploaded one 189-line Python sample and queried service status, A2A/MCP, model review and the sandbox broker. The latter is the relevant evidence for the current integrated application.")
table("Curated benchmark composition", ["Language", "Labeled defects", "Clean cases"], [
    ("Python", "13", "2"), ("JavaScript", "8", "2"), ("TypeScript", "6", "2"),
    ("Java", "7", "2"), ("C/C++", "6", "2"), ("Total", "40", "10"),
], [2.2, 2.1, 2.1])
figure(benchmark_chart(), "Recorded outcomes in the curated 50-scenario benchmark", 6.0)
sub("7.2 Results of the live integration check")
table("Observed Docker inspection pipeline status", ["Stage", "Recorded outcome", "Interpretation"], [
    ("Image build", "Completed in 447.3 seconds", "All five images built in the recorded run."),
    ("Web and upload", "One Python file inspected", "Upload and inspection endpoints responded."),
    ("Redis blackboard", "Connected", "Shared state service was reachable."),
    ("A2A/MCP analyst", "Completed", "Remote analysis stage returned successfully."),
    ("Sandbox probe", "4 checks passed", "A disposable child test container ran."),
    ("Gemini source review", "ReadTimeout", "Model output was not available for this run."),
    ("Patch verification", "0 checks; 0 verified patches", "No inspected patch was behaviorally confirmed."),
], [1.55, 1.65, 3.25])
paragraph("The successful sandbox probe confirms container execution, but it is not a test of a correction to the uploaded file. Likewise, the benchmark's 100% precision and recall are limited to its curated fixtures. Neither figure should be read as proof that every real upload is defect-free or fully repaired.")
sub("7.3 Model review and timeout")
paragraph("The latest recorded model review failed with ReadTimeout. The code initially used a 45-second request timeout; it has since been raised to 150 seconds, and the report now exposes a safe error category. The supplied evidence does not include a successful rerun after this change. Therefore this report records the model stage as unverified in the current integrated run.")
sub("7.4 Safety and regression findings")
paragraph("The evaluator keeps model suggestions unverified when no relevant checks run. The dashboard labels suggested fixes separately from verified patches, and the download and apply-copy endpoints reject a report without a verified diff. The upload handler also restricts archive size and paths before extracting project files. These are implemented controls; a broader security assessment and external penetration test are outside the available evidence.")
sub("7.5 Limitations")
bullets([
    "The model gateway can exceed the configured request timeout, leaving the LLM stage unavailable.",
    "A sandbox probe can pass while the inspected project's own corrections have no applicable tests.",
    "Project-specific dependencies may be absent from the generic Python or C++ sandbox images.",
    "The 50-scenario curated benchmark is too small to establish general accuracy on arbitrary repositories.",
    "The repository's earlier test reports predate the latest source edits; a fresh full test suite result is not included here.",
])

# Chapter 8
chapter("8. Team Responsibility and Self Contribution")
paragraph("The project synopsis lists two candidates. The available repository and run logs do not attribute individual files, tests or experiments to a particular candidate. The matrix below is intentionally left for the candidates to verify before submission.")
table("Candidate contribution matrix for confirmation", ["Activity", "Yashvardhan Singh", "Atharv Jain"], [
    ("Architecture and planning", "To confirm", "To confirm"),
    ("Agent implementation", "To confirm", "To confirm"),
    ("Web interface and API", "To confirm", "To confirm"),
    ("Sandbox and Docker deployment", "To confirm", "To confirm"),
    ("Testing and benchmark", "To confirm", "To confirm"),
    ("Report and presentation", "To confirm", "To confirm"),
], [2.5, 1.95, 1.95])

# Chapter 9
chapter("9. Conclusions")
paragraph("DevPilot implements a multi-language inspection workflow with line-grounded findings, a Redis-backed shared state, A2A analyst dispatch and isolated Docker test execution. The current Docker evidence confirms these infrastructure paths, including four passing checks in a child sandbox container. It also exposes a remaining integration limit: Gemini source review timed out, and the uploaded sample produced no verified patch in that run.")
paragraph("The project therefore demonstrates the architecture and several working interfaces, but it has not yet demonstrated a complete model-assisted correction for the recorded upload. The next validation step is to repeat the live checker after the timeout adjustment, then inspect a project with a relevant test file and record both the issue-level verification result and the exported diff. A fresh full test suite and a broader, independently labeled repository set would strengthen the evaluation.")

# References
chapter("References")
references = [
    "[1] Jimenez, C. E. et al. SWE-bench: Can Language Models Resolve Real-World GitHub Issues? ICLR 2024. https://arxiv.org/abs/2310.06770",
    "[2] Yao, S. et al. ReAct: Synergizing Reasoning and Acting in Language Models. ICLR 2023. https://arxiv.org/abs/2210.03629",
    "[3] Model Context Protocol. Specification and documentation. https://modelcontextprotocol.io/",
    "[4] Agent2Agent Protocol. Specification and documentation. https://a2a-protocol.org/",
    "[5] Google Gen AI Python SDK. Official documentation. https://googleapis.github.io/python-genai/",
    "[6] DevPilot repository. Project synopsis, source code, benchmark/results/polyglot_50_benchmark_results.json and Docker integration checker. November 2026.",
]
for item in references:
    paragraph(item)

# Appendix
chapter("Appendix")
sub("A.1 Primary REST endpoints")
table("Primary REST endpoints", ["Method", "Path", "Purpose"], [
    ("GET", "/api/health", "Service and dependency status"),
    ("POST", "/api/upload", "Stage file or ZIP input"),
    ("POST", "/api/upload-folder", "Stage a project directory"),
    ("POST", "/api/inspect", "Run source inspection"),
    ("GET", "/api/download-corrected/{run_id}", "Export a verified corrected ZIP"),
    ("POST", "/api/apply-copy/{run_id}", "Apply verified fixes to a copy"),
    ("POST", "/rpc", "A2A JSON-RPC dispatch"),
], [0.65, 2.7, 3.1])
sub("A.2 Structured report fields")
table("Inspection report data", ["Field", "Meaning"], [
    ("run_id", "Identifier for the inspection run"),
    ("issues", "Line-grounded findings and per-issue verification status"),
    ("tests_summary", "Sandbox, LLM and MCP stage outcomes"),
    ("unified_patch", "Diff generated only for verified changes"),
    ("coverage_report", "Files, functions and finding coverage summary"),
], [1.7, 4.75])
sub("A.3 Repository structure")
table("Relevant project paths", ["Path", "Purpose"], [
    ("src/web/app.py", "FastAPI upload, inspection, health and export endpoints"),
    ("src/agents/crewai/coordinator.py", "Inspection and debugging orchestration"),
    ("src/agents/google_adk/", "Specialist worker modules"),
    ("src/mcp_tools/", "AST, vector, search and sandbox tool boundary"),
    ("src/blackboard/", "Redis and in-memory run state"),
    ("docker/docker-compose.yml", "Web, Redis, worker, broker and image services"),
    ("scripts/check_pipeline.py", "Live upload and integration check"),
    ("benchmark/results/", "Curated detector benchmark artifacts"),
], [2.65, 3.8])
sub("A.4 Commands to reproduce the results")
for line in [
    r"cd E:\ageennnnntsss\DevPilot_final",
    r"docker compose --env-file .env -f docker\docker-compose.yml up --build -d",
    r"docker compose --env-file .env -f docker\docker-compose.yml exec devpilot-web python scripts/check_pipeline.py",
    r"docker compose --env-file .env -f docker\docker-compose.yml logs --tail 80 devpilot-web sandbox-broker",
]:
    p = paragraph(line, align=WD_ALIGN_PARAGRAPH.LEFT)
    for run in p.runs:
        run.font.name, run.font.size = "Consolas", Pt(8.5)
sub("A.5 Acceptance checks")
table("Acceptance checks for the next live run", ["No.", "Check"], [
    ("1", "Health shows Redis and Docker sandbox connected."),
    ("2", "Uploaded file count and path match the submitted sample."),
    ("3", "A2A/MCP analysis reports completed."),
    ("4", "LLM review reports completed or partial with files reviewed above zero."),
    ("5", "Sandbox probe passes four behavioral checks."),
    ("6", "An exported patch is present only after relevant issue checks pass."),
], [0.55, 5.9])

# Extended appendices retain the source report's academic structure while making
# the evidence and the limits of the available run independently inspectable.
chapter("Appendix B. Evidence Register")
paragraph("The report distinguishes implementation evidence, curated benchmark evidence and a live Docker run. These sources answer different questions. Source code shows that a stage exists; a fixture benchmark measures the selected cases; a live run shows what actually executed for one uploaded sample. None can substitute for the other.")
table("Evidence register and permitted inference", ["Evidence", "What it supports", "Limit"], [
    ("Project synopsis", "Project objective, authors and intended architecture", "Intent does not prove execution"),
    ("Source tree", "Implemented interfaces and control flow", "A branch may remain unexercised"),
    ("Compose files", "Declared services and dependencies", "Startup must still be observed"),
    ("Curated 50-case results", "Detector outcomes on labeled fixtures", "Not a real-repository accuracy estimate"),
    ("Live Docker checker", "Observed upload, worker, Redis and sandbox stages", "One run and one uploaded sample"),
    ("Web UI", "Presentation of report fields", "A displayed claim needs backend evidence"),
], [1.35, 2.7, 2.4])
paragraph("For this report, the strongest positive observation is that the recorded Docker integration check built the images and exercised the web, Redis, A2A/MCP and sandbox stages. The strongest negative observation is the Gemini ReadTimeout during source review. The report therefore does not count that run as a successful end-to-end LLM inspection. The checker showed no issue-specific isolated tests and no verified patch, which is consistent with the failed review stage.")
paragraph("A future evidence package should save the uploaded sample hash, run identifier, container image digest, redacted stage logs, API response, corrected ZIP if produced, and test output. This would let a reviewer connect every reported result to the exact code and execution that produced it.")

chapter("Appendix C. Interface Contracts")
paragraph("DevPilot crosses several process boundaries. A reliable inspection requires each boundary to preserve a run identifier, the staged source path and a clear stage outcome. The table records the expected contract at a level that can be checked without relying on the visual dashboard alone.")
table("Boundary and observable contract", ["Boundary", "Input", "Observable output"], [
    ("Browser to web API", "A file, archive or project path", "Upload identifier and staged path"),
    ("Web to coordinator", "Staged source and run settings", "Run state with stage summaries"),
    ("Coordinator to workers", "Task and project context", "A2A response linked to the same run"),
    ("Worker to MCP tools", "Source path and tool request", "Structured analysis result"),
    ("Coordinator to Gemini", "Bounded source chunks", "Review findings or explicit error status"),
    ("Coordinator to broker", "Candidate and isolated check", "Exit status, output and timing"),
    ("Web to export", "Verified run identifier", "Corrected copy or an explicit rejection"),
], [1.5, 2.15, 2.8])
paragraph("An empty model response, timeout or malformed response should be represented as a distinct outcome. The system must not silently replace that outcome with a fixture finding, because the user would then see results unrelated to the uploaded project. Similarly, a correction proposal is separate from an applied change. The corrected archive and unified diff should include only changes that satisfy the verification gate.")
paragraph("The web endpoint can return HTTP 200 for a completed inspection request even when one internal review stage failed. Consequently, API success must be read together with the stage summary, reviewed-file count, issue statuses and sandbox result. This distinction is central to interpreting the recorded run.")

chapter("Appendix D. Inspection Walkthrough")
paragraph("This walkthrough follows the available pipeline design from submitted source to displayed report. It describes the checks a reviewer should make at each step and identifies the point where the latest recorded execution stopped short of a complete model-assisted result.")
table("Inspection stages and review questions", ["Step", "Stage", "Review question"], [
    ("1", "Upload and staging", "Do file count and paths match the submitted sample?"),
    ("2", "Project mapping", "Were language and manifest signals derived from that sample?"),
    ("3", "Static analysis", "Does each finding point to an existing line?"),
    ("4", "A2A/MCP analysis", "Did the worker finish for the same run identifier?"),
    ("5", "Gemini review", "How many files were reviewed, and what is its status?"),
    ("6", "Candidate correction", "Is the diff limited to the cited issue?"),
    ("7", "Isolated execution", "Did a relevant check actually run in Docker?"),
    ("8", "Export and display", "Do UI labels match backend verification fields?"),
], [0.55, 1.65, 4.25])
paragraph("In the recorded check, the first, fourth and sandbox-probe stages produced evidence of execution. Gemini source review reported ReadTimeout. That result means the run cannot establish that the model inspected the uploaded file completely. It also prevents the run from establishing a verified correction, because no relevant issue-specific test or patch was recorded. The UI should show this as a partial inspection with the reason visible.")
paragraph("To repeat the walkthrough, run the integration checker against a controlled sample with a known defect and a relevant test. Save both the API JSON and the web view. Compare their counts, paths, statuses and diff. A mismatch is a report-mapping defect even if the detector itself is correct.")

chapter("Appendix E. Trust Boundaries")
paragraph("Uploaded repositories and model responses are untrusted inputs. DevPilot therefore needs separate controls at ingestion, source analysis, sandbox execution and export. These controls are directly relevant to the project objective because incorrect inspection output can mislead a developer even when it does not execute malicious code.")
table("Trust boundary review", ["Boundary", "Risk", "Required check"], [
    ("Archive extraction", "Path traversal or unexpected files", "Keep extracted paths inside the run directory"),
    ("Source to model", "Prompt injection in comments", "Treat source as data and ground claims in lines"),
    ("Model to report", "Invented paths, lines or fixes", "Validate every cited file and line"),
    ("Model to patch", "Broad or syntactically invalid edits", "Constrain diff and validate syntax"),
    ("Patch to sandbox", "Unsafe execution on the host", "Use broker-launched isolated container"),
    ("Sandbox to export", "Unverified output appears corrected", "Require relevant check results before export"),
], [1.3, 2.2, 2.95])
paragraph("The Docker probe in the live checker exercises sandbox behavior, but it is not the same as running an issue-specific regression check on a proposed patch. The report uses those labels separately. A structural or syntax pass can support a narrower claim; it cannot establish that the original defect was fixed for all inputs.")
paragraph("A reviewer should also confirm that secrets used for Gemini and other external services are supplied through environment configuration and are omitted from logs, report artifacts and downloadable project copies. Configuration presence should be reported without exposing credential values.")

chapter("Appendix F. Verification Protocol")
paragraph("Verification should be proportional to the finding. A line-grounded static pattern is evidence that a known risky construct exists. It is not, by itself, evidence that a proposed patch behaves correctly. The protocol below separates detection, patch construction and empirical validation.")
table("Finding verification levels", ["Level", "Evidence", "Permitted report label"], [
    ("Detected", "Rule or model identifies a candidate at an existing line", "Finding proposed"),
    ("Grounded", "Path, line and source excerpt match the upload", "Source-grounded finding"),
    ("Patch parsed", "Edited file passes language syntax check", "Syntax validated"),
    ("Regression tested", "Relevant failing case passes after the patch", "Issue-specific check passed"),
    ("Project tested", "Relevant project suite passes in isolated container", "Verified within tested scope"),
], [1.2, 3.45, 1.8])
paragraph("For Python, syntax validation can be performed without importing the module; behavioral tests should use the project's test command in the sandbox. Other languages need their own parser, compiler or test runner. The system should record when a language has no configured verifier, rather than presenting an unrun check as a pass. A failed verifier must preserve its output so the developer can inspect the cause.")
paragraph("The corrected project export must be generated from the verified file set, with a unified diff that identifies every modification. The original upload should remain available separately for comparison. If a candidate patch fails syntax or regression checks, its status should remain rejected or unverified and it should not enter the corrected export.")
paragraph("This protocol explains why the recorded zero issue-specific checks and zero verified patches do not prove a defect-free upload. They show that the validation stage had no accepted candidate to test in that run.")

chapter("Appendix G. Timeout Analysis")
paragraph("The latest available Docker integration result records a Gemini ReadTimeout during source review. A read timeout means the client did not receive the expected response within the configured wait; it does not, on its own, identify whether the delay arose from model latency, request size, a network intermediary or service load. The report therefore records the symptom without assigning an unsupported root cause.")
table("Timeout investigation plan", ["Check", "Observation to capture", "Interpretation"], [
    ("Request size", "Files and bytes sent per chunk", "Large prompts may need smaller batches"),
    ("Timing", "Start, first response and timeout times", "Locate the stalled stage"),
    ("Client settings", "Model name, retry and timeout settings", "Check configuration used by container"),
    ("Service response", "Status or exception class, redacted", "Distinguish timeout from API error"),
    ("Repeatability", "Three runs of the same small sample", "Separate intermittent from stable failure"),
    ("Partial output", "Reviewed-file count and findings", "Assess what the user can safely rely on"),
], [1.3, 2.85, 2.3])
paragraph("The source was subsequently adjusted to allow a longer model wait, but the available evidence does not include a successful live recheck after that change. The next run must use a rebuilt container image and capture the actual review status. If the timeout repeats, reduce chunk size or concurrency and compare response times while preserving the same sample. Each retry should be bounded and should preserve the final error in the report.")
paragraph("A partial result can still display grounded static findings. It should visibly state that model review was incomplete and should avoid promising an autonomous corrected project unless verification has actually succeeded.")

chapter("Appendix H. Next Evaluation")
paragraph("The curated 50-case benchmark is useful for regression testing known patterns, but a stronger evaluation should test complete repositories and multiple failure modes. The plan below turns the current architecture claims into measurable acceptance criteria.")
table("Evaluation plan", ["Study", "Input", "Success measure"], [
    ("Small known defect", "One-file Python sample with a test", "Grounded finding and relevant test"),
    ("Multi-file upload", "Mixed source and manifest", "Correct file count and paths"),
    ("No-defect sample", "Labeled clean project", "No fabricated verified findings"),
    ("Model timeout", "Delayed or unavailable Gemini response", "Explicit partial status and no fake output"),
    ("Unsafe patch", "Candidate that fails syntax", "Rejected export with visible reason"),
    ("Sandbox boundary", "Behavioral isolation probe", "Broker result recorded without host fallback"),
    ("Repeat runs", "Same upload and settings", "Stable counts or explained variation"),
], [1.55, 2.25, 2.65])
paragraph("For each study, retain the submitted input, expected outcome, actual JSON report, stage logs, test output, final diff and user-facing screenshot. Report detection precision and recall only on a labeled set, with the denominator and selection method stated. Report latency by stage rather than only total duration. This allows a reader to see whether time is spent in source mapping, model review, isolated checks or export.")
paragraph("The next practical milestone is one complete live inspection in which the model reviews the uploaded source, a proposed change passes a relevant isolated test, and the corrected archive contains exactly that verified change. Until that evidence is saved, the report's conclusion remains limited to the successful stages and the documented timeout.")

doc.core_properties.title = "DevPilot Final Project Report"
doc.core_properties.subject = "Multi-Agent Autonomous Code Inspection and Debugging"
doc.core_properties.author = "Yashvardhan Singh and Atharv Jain"
doc.save(OUTPUT)
print(OUTPUT)
