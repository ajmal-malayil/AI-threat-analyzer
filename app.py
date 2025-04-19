# -*- coding: utf-8 -*-
import gradio as gr
import os
import fitz  # PyMuPDF
import pandas as pd
from fpdf import FPDF
from pathlib import Path
import google.generativeai as genai
import json
from enum import Enum
import zipfile
from datetime import datetime
import re
import time
import html
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# 🔐 Load API keys from .env
API_KEYS = os.getenv("GEMINI_KEYS", "").split(",")
API_KEYS = [key.strip() for key in API_KEYS if key.strip()]

if not API_KEYS:
    raise ValueError("❌ No Gemini API keys found. Please set GEMINI_KEYS in your .env file.")

current_key_index = 0
try:
    os.environ["GOOGLE_API_KEY"] = API_KEYS[current_key_index]
    genai.configure(api_key=API_KEYS[current_key_index])
    print(f"Configured GenAI with API Key index {current_key_index}")
except Exception as e:
    print(f"🚨 Fatal Error: Could not configure Generative AI. Error: {e}")
    import sys
    sys.exit(1)

REPORTS_DIR = "analyzed_reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

class AIProvider(Enum):
    GEMINI = "Gemini"
    OPENAI = "OpenAI"  # Placeholder for future
    CLAUDE = "Claude"  # Placeholder for future
    DEEPSEEK = "DeepSeek"  # Placeholder for future

# --------------------------------------------------------------------------
# Core Functions (File Processing, AI Interaction, PDF Generation)
# --------------------------------------------------------------------------

def extract_content(file_path):
    """Extracts text content from supported file types."""
    ext = Path(file_path).suffix.lower()
    file_name = Path(file_path).name
    print(f"Attempting to extract content from: {file_name} (type: {ext})")
    try:
        if ext == ".pdf":
            doc = fitz.open(file_path)
            text = ''.join(page.get_text("text") for page in doc)
            doc.close()
            if not text.strip():
                return "📄 PDF contained no extractable text."
            print(f"Successfully extracted text from PDF '{file_name}'. Length: {len(text)}")
            return text
        elif ext in [".xls", ".xlsx"]:
            xls = pd.ExcelFile(file_path)
            all_sheets_text = []
            if not xls.sheet_names:
                return "📊 Excel file seems empty or has no sheets."
            for sheet_name in xls.sheet_names:
                try:
                    df = pd.read_excel(xls, sheet_name=sheet_name)
                    if not df.empty:
                        all_sheets_text.append(f"--- Sheet: {sheet_name} ---\n{df.to_string()}\n")
                    else:
                        all_sheets_text.append(f"--- Sheet: {sheet_name} (empty) ---\n")
                except Exception as sheet_err:
                    all_sheets_text.append(f"--- Sheet: {sheet_name} (Error reading: {sheet_err}) ---\n")
            if not all_sheets_text:
                return "📊 Excel file contained no data in readable sheets."
            full_text = "\n".join(all_sheets_text)
            print(f"Successfully extracted data from Excel '{file_name}'. Length: {len(full_text)}")
            return full_text
        elif ext in [".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".md", ".rtf"]:
            encodings_to_try = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
            content = None
            for encoding in encodings_to_try:
                try:
                    with open(Path(file_path), 'r', encoding=encoding) as f:
                        content = f.read()
                    print(f"Successfully read '{file_name}' with encoding '{encoding}'. Length: {len(content)}")
                    return content
                except UnicodeDecodeError:
                    continue
                except Exception as read_err:
                    return f"❌ Error reading file '{file_name}': {read_err}"
            return f"❌ Error reading file: Could not decode '{file_name}' using tried encodings."
        else:
            return f"❌ Unsupported file format: {ext}"
    except fitz.FileNotFoundError:
        return f"❌ Error: File not found '{file_name}'"
    except Exception as e:
        print(f"🚨 Unexpected error reading file '{file_name}': {e}")
        return f"❌ Unexpected error reading file '{file_name}': {e}"

def build_prompt(content):
    """Creates the prompt for the Gemini model."""
    max_prompt_content_length = 25000
    truncated_content = content[:max_prompt_content_length]
    if len(content) > max_prompt_content_length:
        truncated_content += "\n\n[CONTENT TRUNCATED DUE TO LENGTH]"
    return f"""
Analyze the following log content meticulously. Your primary task is to identify potential cybersecurity threats or noteworthy events based *only* on the provided text.

Log Content Snippet:
--- START LOG ---
{truncated_content}
--- END LOG ---

Instructions:
1. Carefully review the log content.
2. Identify the most significant security-related event or finding. If no threat is apparent, look for informational events (e.g., successful login, system start).
3. Format your analysis *strictly* as a single JSON object.
4. Do *not* include any text, explanation, notes, apologies, or markdown formatting (like ```json or ```) before or after the JSON object.
5. Ensure all keys and string values within the JSON are enclosed in double quotes (e.g., "key": "value").
6. Use "N/A" (as a string) for any fields where the information cannot be reasonably inferred from the provided log content.
7. Adhere precisely to the structure specified below.

Required JSON Structure:
{{
    "threat_level": "LOW | MEDIUM | HIGH | CRITICAL | INFO | N/A",
    "detected_threat_type": "Specific threat type (e.g., Malware Execution Attempt, Failed Login Brute Force, Potential Phishing URL, Data Access Anomaly, Policy Violation, Successful Admin Login, System Update, N/A)",
    "affected_system": "Relevant hostname, IP address, service, filename, username, or N/A",
    "summary": "A concise (1-2 sentence) description of the core event identified in the log.",
    "recommended_actions": [
        "Clear, actionable step 1 based on the finding (e.g., 'Investigate IP 1.2.3.4', 'Reset password for user admin', 'Verify patch status', 'No action needed')",
        "Actionable step 2 (if applicable, otherwise keep array empty)"
    ],
    "risk_score": "An estimated numerical score from 0 (no risk) to 100 (critical), based on threat level and context. Use '0' if level is INFO or N/A.",
    "mitre_mapping": [
        "Relevant MITRE ATT&CK Technique ID (e.g., 'T1059.001' for PowerShell)",
        "Relevant Technique ID 2 (if applicable, otherwise empty array [])"
    ]
}}
"""

def parse_json_response(response_text):
    """Parse and validate the JSON response."""
    if not response_text:
        raise ValueError("Received empty response text from AI.")
    cleaned_text = response_text.strip()
    print(f"Attempting to extract JSON from response (first 500 chars): {cleaned_text[:500]}")
    cleaned_text = re.sub(r'^```json\s*', '', cleaned_text, flags=re.IGNORECASE | re.DOTALL)
    cleaned_text = re.sub(r'\s*```\s*$', '', cleaned_text, flags=re.DOTALL)
    cleaned_text = cleaned_text.strip()
    if not cleaned_text.startswith('{') or not cleaned_text.endswith('}'):
        start_index = cleaned_text.find('{');
        end_index = cleaned_text.rfind('}')
        if (start_index != -1 and end_index != -1 and end_index > start_index):
            json_str = cleaned_text[start_index: end_index + 1];
            print("Warning: Extracted JSON content.")
        else:
            raise json.JSONDecodeError(f"No valid JSON object structure found. Start: {cleaned_text[:200]}...",
                                     cleaned_text, 0)
    else:
        json_str = cleaned_text
    try:
        parsed_json = json.loads(json_str);
        print("Successfully parsed JSON.");
        return parsed_json
    except json.JSONDecodeError as e:
        error_pos_context = json_str[max(0, e.pos - 20):min(len(json_str), e.pos + 20)]
        print(f"🚨 JSON Decode Error: {e.msg} near '{error_pos_context}'.");
        raise json.JSONDecodeError(f"Failed to decode JSON: {e.msg} near '{error_pos_context}'", json_str,
                                     e.pos) from e

def generate_pdf_report(file_name, json_data):
    """Generate a PDF report."""
    pdf = None;
    output_path = None
    font_path = 'DejaVuSansCondensed.ttf';
    font_path_bold = 'DejaVuSansCondensed-Bold.ttf'
    print(f"🐞 [PDF START] Starting PDF generation for: {file_name}")  # Explicit start log
    try:
        print(f"🐞 [PDF CHECK] Font path: {font_path}, exists: {os.path.exists(font_path)}")
        print(f"🐞 [PDF CHECK] Font path bold: {font_path_bold}, exists: {os.path.exists(font_path_bold)}")
        if not os.path.exists(font_path) or not os.path.exists(font_path_bold):
            error_message = f"🚨 [PDF ERROR] Font files not found. Place '{font_path}' and '{font_path_bold}' alongside app.py."
            print(error_message)
            raise FileNotFoundError(error_message)

        pdf = FPDF()
        print("🐞 [PDF INIT] FPDF initialized.")  # Log after initialization
        pdf.add_font('DejaVu', '', font_path)
        print("🐞 [PDF FONT] DejaVu regular added.")  # Log after adding font
        pdf.add_font('DejaVu', 'B', font_path_bold)
        print("🐞 [PDF FONT] DejaVu bold added.")  # Log after adding font
        pdf.add_page()
        print("🐞 [PDF PAGE] Page added.")  # Log after adding page
        pdf.set_margins(15, 15, 15)
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_font("DejaVu", 'B', 16)
        pdf.cell(w=0, h=10, text="Cybersecurity Threat Analysis Report", align='C', new_x="LMARGIN",
                 new_y="NEXT")
        pdf.set_font("DejaVu", '', 11)
        safe_display_name = html.escape(file_name.encode('latin-1', 'replace').decode('latin-1'))  # Ensure html is imported
        pdf.cell(w=0, h=8, text=f"Log File Analyzed: {safe_display_name}", align='C', new_x="LMARGIN",
                 new_y="NEXT")
        pdf.ln(8)
        pdf.set_font("DejaVu", 'B', 13)
        pdf.cell(w=0, h=8, text="Analysis Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(4)
        report_fields = {"Threat Level": json_data.get("threat_level", "N/A"),
                         "Risk Score": str(json_data.get("risk_score", "N/A")),
                         "Detected Threat / Event": json_data.get("detected_threat_type", "N/A"),
                         "Affected System / Entity": json_data.get("affected_system", "N/A"),
                         "Event Summary": json_data.get("summary", "N/A"),
                         "MITRE ATT&CK Mapping": json_data.get("mitre_mapping", []),
                         "Recommended Actions": json_data.get("recommended_actions", [])}
        field_label_width = 60
        value_start_x = 15 + field_label_width + 2
        for key, value in report_fields.items():
            current_y = pdf.get_y()
            pdf.set_font("DejaVu", 'B', 11)
            pdf.cell(w=field_label_width, h=7, text=f"{key}:")
            pdf.set_font("DejaVu", '', 11)
            pdf.set_xy(value_start_x, current_y)
            available_width = pdf.w - value_start_x - pdf.r_margin
            if isinstance(value, list):
                if value:
                    first_item = True
                    for item in value:
                        if not first_item:
                            pdf.set_x(value_start_x)
                        pdf.multi_cell(w=available_width, h=7, text=f"• {str(item)}")
                        first_item = False
                    pdf.set_x(15)
                else:
                    pdf.multi_cell(w=available_width, h=7, text="N/A")
                    pdf.set_x(15)
            else:
                pdf.multi_cell(w=available_width, h=7, text=str(value))
            if pdf.get_y() < current_y + 7:
                pdf.set_y(current_y + 7)
            pdf.ln(3)

        pdf.ln(10)
        pdf.set_font("DejaVu", '', 9)
        pdf.set_text_color(128, 128, 128)
        pdf.cell(w=0, h=10, text=f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} using Gemini AI",
                 align='C', new_x="LMARGIN", new_y="NEXT")
        safe_file_stem = re.sub(r'[\\/*?:"<>|]', "_", Path(file_name).stem)
        timestamp_suffix = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_filename = f"{safe_file_stem}_report_{timestamp_suffix}.pdf"
        output_path = Path(REPORTS_DIR) / output_filename
        print(f"🐞 [PDF SAVE] Attempting to create reports directory: {REPORTS_DIR}")
        os.makedirs(REPORTS_DIR, exist_ok=True)
        print(f"🐞 [PDF SAVE] Attempting to save PDF to: {output_path}")
        pdf.output(str(output_path))
        print(f"🐞 [PDF SAVE] PDF output command completed. Checking if file exists: {output_path.exists()}")
        if not output_path.exists():
            error_message = f"🚨 [PDF ERROR] Failed to create PDF file at {output_path}."
            print(error_message)
            raise FileNotFoundError(error_message)
        print(f"✅ [PDF END] Successfully generated PDF report: {output_path}")
        return str(output_path)
    except FileNotFoundError as fnf_err:
        print(f"🚨 [PDF ERROR] (FileNotFound): {fnf_err}")
        return None
    except Exception as e:
        print(f"🚨 [PDF ERROR] (General Exception): {e}")
        return None

def safe_generate_content(model=None, prompt="", max_retries=3):
    """Safely generate content using Gemini AI, with API key rotation."""
    global current_key_index
    initial_key_index = current_key_index

    for attempt in range(max_retries):
        current_api_key = API_KEYS[current_key_index]
        print(f"\n🔁 Attempt {attempt + 1}/{max_retries} — Using Gemini Key #{current_key_index + 1}")

        try:
            # Reconfigure model each time with current key
            genai.configure(api_key=current_api_key)
            model = genai.GenerativeModel("models/gemini-1.5-flash-latest")

            generation_config = genai.GenerationConfig(
                response_mime_type="text/plain",
                temperature=0.1,
                max_output_tokens=4096
            )

            safety_settings = [
                {"category": c, "threshold": "BLOCK_MEDIUM_AND_ABOVE"} for c in [
                    "HARM_CATEGORY_HARASSMENT",
                    "HARM_CATEGORY_HATE_SPEECH",
                    "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "HARM_CATEGORY_DANGEROUS_CONTENT"
                ]
            ]

            print("📡 Sending request to Gemini API...")
            response = model.generate_content(
                prompt,
                generation_config=generation_config,
                safety_settings=safety_settings,
                request_options={'timeout': 120}
            )

            print("✅ Response received.")

            # Handle safety block
            if not response.candidates:
                block_reason = "Not specified"
                try:
                    block_reason = response.prompt_feedback.block_reason.name if response.prompt_feedback and response.prompt_feedback.block_reason else "Not specified"
                except Exception:
                    pass
                raise Exception(f"🛑 Content generation blocked due to safety settings. Reason: {block_reason}")

            if hasattr(response, 'text') and response.text:
                print(f"🎯 Success with key #{current_key_index + 1}")
                return response

            raise Exception("Generation succeeded but unexpected response format (no text).")

        except Exception as e:
            error_str = str(e).lower()
            print(f"🚨 Error with key #{current_key_index + 1}: {e}")

            is_quota_error = any(term in error_str for term in ["quota", "429", "resource has been exhausted"])
            is_auth_error = any(term in error_str for term in
                                 ["permission denied", "api key not valid", "api key invalid", "401", "403"])
            is_safety_block = "blocked by safety settings" in error_str or "response was blocked" in error_str

            if is_safety_block:
                raise e  # Don't retry safety blocks
            elif is_quota_error or is_auth_error:
                # Rotate to next key
                current_key_index = (current_key_index + 1) % len(API_KEYS)
                if current_key_index == initial_key_index and attempt > 0:
                    raise Exception("🔁 All API keys exhausted or failed.") from e
                print(f"🔃 Switching to backup key #{current_key_index + 1}...")
                time.sleep(2)
                continue
            else:
                raise e

    raise Exception(f"❌ Failed after {max_retries} attempts.")

def cleanup_old_reports():
    """Delete old reports."""
    now = time.time();
    cutoff = now - (24 * 60 * 60);
    count = 0
    print(f"🧹 Starting cleanup of old reports in '{REPORTS_DIR}'...")
    try:
        if not os.path.isdir(REPORTS_DIR):
            print("  Info: Reports directory does not exist.");
            return
        for filename in os.listdir(REPORTS_DIR):
            if filename.lower().endswith((".pdf", ".zip")):
                file_path = os.path.join(REPORTS_DIR, filename)
                try:
                    if os.path.isfile(file_path) and os.path.getmtime(file_path) < cutoff:
                        os.remove(file_path);
                        print(f"  - Deleted old report: {filename}");
                        count += 1
                except Exception as e:
                    print(f"  - ⚠️ Error processing/deleting {filename}: {e}")
        if count > 0:
            print(f"🧹 Cleanup finished. Deleted {count} old report file(s).")
        else:
            print("🧹 No old report files found matching criteria for deletion.")
    except Exception as e:
        print(f"🚨 Error during cleanup: {e}")

def analyze_multiple_files(files, selected_model, progress=gr.Progress(track_tqdm=True)):
    """Analyze multiple files and generate report/log."""
    start_time = time.time()
    if files is None:
        files = []
    elif not isinstance(files, list):
        files = [files]

    # --- Initial checks return explicit updates ---
    if not files:
        return {
            out_status: gr.update(value="❌ No files uploaded."),
            out_download: gr.update(visible=False),
            out_file_results: gr.update(value="<p style='color: orange;'>Please upload at least one file.</p>"),
            out_processing_log: gr.update(value="")
        }
    total_files = len(files);
    print(f"Received {total_files} file(s) for analysis.")
    if selected_model != AIProvider.GEMINI.value:
        msg = f"⚠️ Model '{html.escape(selected_model)}' not supported."
        return {
            out_status: gr.update(value=msg), out_download: gr.update(visible=False),
            out_file_results: gr.update(value=f"<p style='color: orange;'>{msg} Please select '{AIProvider.GEMINI.value}'.</p>"),
            out_processing_log: gr.update(value="")
        }
    try:
        genai.configure(api_key=API_KEYS[current_key_index]);
        model = genai.GenerativeModel("models/gemini-1.5-flash-latest")
        print(f"Using Gemini model: 'gemini-1.5-flash-latest' with API key index {current_key_index}")
    except Exception as e:
        msg = f"🚨 Failed to initialize AI Model: {html.escape(str(e))}"
        return {
            out_status: gr.update(value=msg), out_download: gr.update(visible=False),
            out_file_results: gr.update(value=f"<p style='color: red;'>{msg}</p>"),
            out_processing_log: gr.update(value="")
        }
    # --- End Initial Checks ---

    analysis_results = [];
    pdf_files_generated = [];
    error_count = 0;
    success_count = 0
    # Initialize summary_log here
    summary_log = f"📊 Analysis started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} for {total_files} file(s)\n🤖 Model: {selected_model}\n⚠️ Reports auto-delete after 24h.\n\n"

    for i, file_obj in enumerate(progress.tqdm(files, desc="Analyzing Files")):
        file_path = Path(file_obj.name) if hasattr(file_obj, 'name') else Path(str(file_obj))
        file_name_display = file_path.name
        current_file_log_prefix = f"📄 File {i + 1}/{total_files} ('{file_name_display}'):"
        print(f"\n--- {current_file_log_prefix} ---")
        file_result = {"filename": file_name_display, "status": "Processing", "details": "", "json_data": None}

        # --- Append processing steps to summary_log ---
        summary_log += f"--- {current_file_log_prefix} ---\n"

        content = extract_content(str(file_path))
        if isinstance(content, str) and (
                content.startswith("❌") or content.startswith("📄") or content.startswith("📊")):
            file_result["status"] = "❌ Extraction Error";
            file_result["details"] = content
            summary_log += f"Extraction Failed: {content}\n"  # Add to log
            analysis_results.append(file_result);
            error_count += 1
            print(f"{current_file_log_prefix} Failed extraction: {content}");
            continue
        else:
            summary_log += f"Content extracted successfully (Length: {len(content)}).\n"  # Add success to log

        prompt = build_prompt(content)
        summary_log += "Sending request to AI...\n"  # Add to log
        try:
            response = safe_generate
Okay, I've reviewed your code. Here's a revised version with some debugging enhancements and potential fixes to address the logging and PDF generation issues.


```python
# -*- coding: utf-8 -*-
import gradio as gr
import os
import fitz  # PyMuPDF
import pandas as pd
from fpdf import FPDF
from pathlib import Path
import google.generativeai as genai
import json
from enum import Enum
import zipfile
from datetime import datetime
import re
import time
import html
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# 🔐 Load API keys from .env
API_KEYS = os.getenv("GEMINI_KEYS", "").split(",")
API_KEYS = [key.strip() for key in API_KEYS if key.strip()]

if not API_KEYS:
    raise ValueError("❌ No Gemini API keys found. Please set GEMINI_KEYS in your .env file.")

current_key_index = 0
try:
    os.environ["GOOGLE_API_KEY"] = API_KEYS[current_key_index]
    genai.configure(api_key=API_KEYS[current_key_index])
    print(f"Configured GenAI with API Key index {current_key_index}")
except Exception as e:
    print(f"🚨 Fatal Error: Could not configure Generative AI. Error: {e}")
    import sys
    sys.exit(1)

REPORTS_DIR = "analyzed_reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

class AIProvider(Enum):
    GEMINI = "Gemini"
    OPENAI = "OpenAI"  # Placeholder for future
    CLAUDE = "Claude"  # Placeholder for future
    DEEPSEEK = "DeepSeek"  # Placeholder for future

# --------------------------------------------------------------------------
# Core Functions (File Processing, AI Interaction, PDF Generation)
# --------------------------------------------------------------------------

def extract_content(file_path):
    """Extracts text content from supported file types."""
    ext = Path(file_path).suffix.lower()
    file_name = Path(file_path).name
    print(f"Attempting to extract content from: {file_name} (type: {ext})")
    try:
        if ext == ".pdf":
            doc = fitz.open(file_path)
            text = ''.join(page.get_text("text") for page in doc)
            doc.close()
            if not text.strip():
                return "📄 PDF contained no extractable text."
            print(f"Successfully extracted text from PDF '{file_name}'. Length: {len(text)}")
            return text
        elif ext in [".xls", ".xlsx"]:
            xls = pd.ExcelFile(file_path)
            all_sheets_text = []
            if not xls.sheet_names:
                return "📊 Excel file seems empty or has no sheets."
            for sheet_name in xls.sheet_names:
                try:
                    df = pd.read_excel(xls, sheet_name=sheet_name)
                    if not df.empty:
                        all_sheets_text.append(f"--- Sheet: {sheet_name} ---\n{df.to_string()}\n")
                    else:
                        all_sheets_text.append(f"--- Sheet: {sheet_name} (empty) ---\n")
                except Exception as sheet_err:
                    all_sheets_text.append(f"--- Sheet: {sheet_name} (Error reading: {sheet_err}) ---\n")
            if not all_sheets_text:
                return "📊 Excel file contained no data in readable sheets."
            full_text = "\n".join(all_sheets_text)
            print(f"Successfully extracted data from Excel '{file_name}'. Length: {len(full_text)}")
            return full_text
        elif ext in [".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".md", ".rtf"]:
            encodings_to_try = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
            content = None
            for encoding in encodings_to_try:
                try:
                    with open(Path(file_path), 'r', encoding=encoding) as f:
                        content = f.read()
                    print(f"Successfully read '{file_name}' with encoding '{encoding}'. Length: {len(content)}")
                    return content
                except UnicodeDecodeError:
                    continue
                except Exception as read_err:
                    return f"❌ Error reading file '{file_name}': {read_err}"
            return f"❌ Error reading file: Could not decode '{file_name}' using tried encodings."
        else:
            return f"❌ Unsupported file format: {ext}"
    except fitz.FileNotFoundError:
        return f"❌ Error: File not found '{file_name}'"
    except Exception as e:
        print(f"🚨 Unexpected error reading file '{file_name}': {e}")
        return f"❌ Unexpected error reading file '{file_name}': {e}"

def build_prompt(content):
    """Creates the prompt for the Gemini model."""
    max_prompt_content_length = 25000
    truncated_content = content[:max_prompt_content_length]
    if len(content) > max_prompt_content_length:
        truncated_content += "\n\n[CONTENT TRUNCATED DUE TO LENGTH]"
    return f"""
Analyze the following log content meticulously. Your primary task is to identify potential cybersecurity threats or noteworthy events based *only* on the provided text.

Log Content Snippet:
--- START LOG ---
{truncated_content}
--- END LOG ---

Instructions:
1. Carefully review the log content.
2. Identify the most significant security-related event or finding. If no threat is apparent, look for informational events (e.g., successful login, system start).
3. Format your analysis *strictly* as a single JSON object.
4. Do *not* include any text, explanation, notes, apologies, or markdown formatting (like ```json or ```) before or after the JSON object.
5. Ensure all keys and string values within the JSON are enclosed in double quotes (e.g., "key": "value").
6. Use "N/A" (as a string) for any fields where the information cannot be reasonably inferred from the provided log content.
7. Adhere precisely to the structure specified below.

Required JSON Structure:
{{
    "threat_level": "LOW | MEDIUM | HIGH | CRITICAL | INFO | N/A",
    "detected_threat_type": "Specific threat type (e.g., Malware Execution Attempt, Failed Login Brute Force, Potential Phishing URL, Data Access Anomaly, Policy Violation, Successful Admin Login, System Update, N/A)",
    "affected_system": "Relevant hostname, IP address, service, filename, username, or N/A",
    "summary": "A concise (1-2 sentence) description of the core event identified in the log.",
    "recommended_actions": [
        "Clear, actionable step 1 based on the finding (e.g., 'Investigate IP 1.2.3.4', 'Reset password for user admin', 'Verify patch status', 'No action needed')",
        "Actionable step 2 (if applicable, otherwise keep array empty)"
    ],
    "risk_score": "An estimated numerical score from 0 (no risk) to 100 (critical), based on threat level and context. Use '0' if level is INFO or N/A.",
    "mitre_mapping": [
        "Relevant MITRE ATT&CK Technique ID (e.g., 'T1059.001' for PowerShell)",
        "Relevant Technique ID 2 (if applicable, otherwise empty array [])"
    ]
}}
"""

def parse_json_response(response_text):
    """Parse and validate the JSON response."""
    if not response_text:
        raise ValueError("Received empty response text from AI.")
    cleaned_text = response_text.strip()
    print(f"Attempting to extract JSON from response (first 500 chars): {cleaned_text[:500]}")
    cleaned_text = re.sub(r'^```json\s*', '', cleaned_text, flags=re.IGNORECASE | re.DOTALL)
    cleaned_text = re.sub(r'\s*```\s*$', '', cleaned_text, flags=re.DOTALL)
    cleaned_text = cleaned_text.strip()
    if not cleaned_text.startswith('{') or not cleaned_text.endswith('}'):
        start_index = cleaned_text.find('{');
        end_index = cleaned_text.rfind('}')
        if (start_index != -1 and end_index != -1 and end_index > start_index):
            json_str = cleaned_text[start_index: end_index + 1];
            print("Warning: Extracted JSON content.")
        else:
            raise json.JSONDecodeError(f"No valid JSON object structure found. Start: {cleaned_text[:200]}...",
                                     cleaned_text, 0)
    else:
        json_str = cleaned_text
    try:
        parsed_json = json.loads(json_str);
        print("Successfully parsed JSON.");
        return parsed_json
    except json.JSONDecodeError as e:
        error_pos_context = json_str[max(0, e.pos - 20):min(len(json_str), e.pos + 20)]
        print(f"🚨 JSON Decode Error: {e.msg} near '{error_pos_context}'.");
        raise json.JSONDecodeError(f"Failed to decode JSON: {e.msg} near '{error_pos_context}'", json_str,
                                     e.pos) from e

def generate_pdf_report(file_name, json_data):
    """Generate a PDF report."""
    pdf = None;
    output_path = None
    font_path = 'DejaVuSansCondensed.ttf';
    font_path_bold = 'DejaVuSansCondensed-Bold.ttf'
    print(f"🐞 [PDF START] Starting PDF generation for: {file_name}")  # Explicit start log
    try:
        print(f"🐞 [PDF CHECK] Font path: {font_path}, exists: {os.path.exists(font_path)}")
        print(f"🐞 [PDF CHECK] Font path bold: {font_path_bold}, exists: {os.path.exists(font_path_bold)}")
        if not os.path.exists(font_path) or not os.path.exists(font_path_bold):
            error_message = f"🚨 [PDF ERROR] Font files not found. Place '{font_path}' and '{font_path_bold}' alongside app.py."
            print(error_message)
            raise FileNotFoundError(error_message)

        pdf = FPDF()
        print("🐞 [PDF INIT] FPDF initialized.")  # Log after initialization
        pdf.add_font('DejaVu', '', font_path)
        print("🐞 [PDF FONT] DejaVu regular added.")  # Log after adding font
        pdf.add_font('DejaVu', 'B', font_path_bold)
        print("🐞 [PDF FONT] DejaVu bold added.")  # Log after adding font
        pdf.add_page()
        print("🐞 [PDF PAGE] Page added.")  # Log after adding page
        pdf.set_margins(15, 15, 15)
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_font("DejaVu", 'B', 16)
        pdf.cell(w=0, h=10, text="Cybersecurity Threat Analysis Report", align='C', new_x="LMARGIN",
                 new_y="NEXT")
        pdf.set_font("DejaVu", '', 11)
        safe_display_name = html.escape(file_name.encode('latin-1', 'replace').decode('latin-1'))  # Ensure html is imported
        pdf.cell(w=0, h=8, text=f"Log File Analyzed: {safe_display_name}", align='C', new_x="LMARGIN",
                 new_y="NEXT")
        pdf.ln(8)
        pdf.set_font("DejaVu", 'B', 13)
        pdf.cell(w=0, h=8, text="Analysis Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(4)
        report_fields = {"Threat Level": json_data.get("threat_level", "N/A"),
                         "Risk Score": str(json_data.get("risk_score", "N/A")),
                         "Detected Threat / Event": json_data.get("detected_threat_type", "N/A"),
                         "Affected System / Entity": json_data.get("affected_system", "N/A"),
                         "Event Summary": json_data.get("summary", "N/A"),
                         "MITRE ATT&CK Mapping": json_data.get("mitre_mapping", []),
                         "Recommended Actions": json_data.get("recommended_actions", [])}
        field_label_width = 60
        value_start_x = 15 + field_label_width + 2
        for key, value in report_fields.items():
            current_y = pdf.get_y()
            pdf.set_font("DejaVu", 'B', 11)
            pdf.cell(w=field_label_width, h=7, text=f"{key}:")
            pdf.set_font("DejaVu", '', 11)
            pdf.set_xy(value_start_x, current_y)
            available_width = pdf.w - value_start_x - pdf.r_margin
            if isinstance(value, list):
                if value:
                    first_item = True
                    for item in value:
                        if not first_item:
                            pdf.set_x(value_start_x)
                        pdf.multi_cell(w=available_width, h=7, text=f"• {str(item)}")
                        first_item = False
                    pdf.set_x(15)
                else:
                    pdf.multi_cell(w=available_width, h=7, text="N/A")
                    pdf.set_x(15)
            else:
                pdf.multi_cell(w=available_width, h=7, text=str(value))
            if pdf.get_y() < current_y + 7:
                pdf.set_y(current_y + 7)
            pdf.ln(3)

        pdf.ln(10)
        pdf.set_font("DejaVu", '', 9)
        pdf.set_text_color(128, 128, 128)
        pdf.cell(w=0, h=10, text=f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} using Gemini AI",
                 align='C', new_x="LMARGIN", new_y="NEXT")
        safe_file_stem = re.sub(r'[\\/*?:"<>|]', "_", Path(file_name).stem)
        timestamp_suffix = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_filename = f"{safe_file_stem}_report_{timestamp_suffix}.pdf"
        output_path = Path(REPORTS_DIR) / output_filename
        print(f"🐞 [PDF SAVE] Attempting to create reports directory: {REPORTS_DIR}")
        os.makedirs(REPORTS_DIR, exist_ok=True)
        print(f"🐞 [PDF SAVE] Attempting to save PDF to: {output_path}")
        pdf.output(str(output_path))
        print(f"🐞 [PDF SAVE] PDF output command completed. Checking if file exists: {output_path.exists()}")
        if not output_path.exists():
            error_message = f"🚨 [PDF ERROR] Failed to create PDF file at {output_path}."
            print(error_message)
            raise FileNotFoundError(error_message)
        print(f"✅ [PDF END] Successfully generated PDF report: {output_path}")
        return str(output_path)
    except FileNotFoundError as fnf_err:
        print(f"🚨 [PDF ERROR] (FileNotFound): {fnf_err}")
        return None
    except Exception as e:
        print(f"🚨 [PDF ERROR] (General Exception): {e}")
        return None

def safe_generate_content(model=None, prompt="", max_retries=3):
    """Safely generate content using Gemini AI, with API key rotation."""
    global current_key_index
    initial_key_index = current_key_index

    for attempt in range(max_retries):
        current_api_key = API_KEYS[current_key_index]
        print(f"\n🔁 Attempt {attempt + 1}/{max_retries} — Using Gemini Key #{current_key_index + 1}")

        try:
            # Reconfigure model each time with current key
            genai.configure(api_key=current_api_key)
            model = genai.GenerativeModel("models/gemini-1.5-flash-latest")

            generation_config = genai.GenerationConfig(
                response_mime_type="text/plain",
                temperature=0.1,
                max_output_tokens=4096
            )

            safety_settings = [
                {"category": c, "threshold": "BLOCK_MEDIUM_AND_ABOVE"} for c in [
                    "HARM_CATEGORY_HARASSMENT",
                    "HARM_CATEGORY_HATE_SPEECH",
                    "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "HARM_CATEGORY_DANGEROUS_CONTENT"
                ]
            ]

            print("📡 Sending request to Gemini API...")
            response = model.generate_content(
                prompt,
                generation_config=generation_config,
                safety_settings=safety_settings,
                request_options={'timeout': 120}
            )

            print("✅ Response received.")

            # Handle safety block
            if not response.candidates:
                block_reason = "Not specified"
                try:
                    block_reason = response.prompt_feedback.block_reason.name if response.prompt_feedback and response.prompt_feedback.block_reason else "Not specified"
                except Exception:
                    pass
                raise Exception(f"🛑 Content generation blocked due to safety settings. Reason: {block_reason}")

            if hasattr(response, 'text') and response.text:
                print(f"🎯 Success with key #{current_key_index + 1}")
                return response

            raise Exception("Generation succeeded but unexpected response format (no text).")

        except Exception as e:
            error_str = str(e).lower()
            print(f"🚨 Error with key #{current_key_index + 1}: {e}")

            is_quota_error = any(term in error_str for term in ["quota", "429", "resource has been exhausted"])
            is_auth_error = any(term in error_str for term in
                                 ["permission denied", "api key not valid", "api key invalid", "401", "403"])
            is_safety_block = "blocked by safety settings" in error_str or "response was blocked" in error_str

            if is_safety_block:
                raise e  # Don't retry safety blocks
            elif is_quota_error or is_auth_error:
                # Rotate to next key
                current_key_index = (current_key_index + 1) % len(API_KEYS)
                if current_key_index == initial_key_index and attempt > 0:
                    raise Exception("🔁 All API keys exhausted or failed.") from e
                print(f"🔃 Switching to backup key #{current_key_index + 1}...")
                time.sleep(2)
                continue
            else:
                raise e

    raise Exception(f"❌ Failed after {max_retries} attempts.")

def cleanup_old_reports():
    """Delete old reports."""
    now = time.time();
    cutoff = now - (24 * 60 * 60);
    count = 0
    print(f"🧹 Starting cleanup of old reports in '{REPORTS_DIR}'...")
    try:
        if not os.path.isdir(REPORTS_DIR):
            print("  Info: Reports directory does not exist.");
            return
        for filename in os.listdir(REPORTS_DIR):
            if filename.lower().endswith((".pdf", ".zip")):
                file_path = os.path.join(REPORTS_DIR, filename)
                try:
                    if os.path.isfile(file_path) and os.path.getmtime(file_path) < cutoff:
                        os.remove(file_path);
                        print(f"  - Deleted old report: {filename}");
                        count += 1
                except Exception as e:
                    print(f"  - ⚠️ Error processing/deleting {filename}: {e}")
        if count > 0:
            print(f"🧹 Cleanup finished. Deleted {count} old report file(s).")
        else:
            print("🧹 No old report files found matching criteria for deletion.")
    except Exception as e:
        print(f"🚨 Error during cleanup: {e}")

def analyze_multiple_files(files, selected_model, progress=gr.Progress(track_tqdm=True)):
    """Analyze multiple files and generate report/log."""
    start_time = time.time()
    if files is None:
        files = []
    elif not isinstance(files, list):
        files = [files]

    # --- Initial checks return explicit updates ---
    if not files:
        return {
            out_status: gr.update(value="❌ No files uploaded."),
            out_download: gr.update(visible=False),
            out_file_results: gr.update(value="<p style='color: orange;'>Please upload at least one file.</p>"),
            out_processing_log: gr.update(value="")
        }
    total_files = len(files);
    print(f"Received {total_files} file(s) for analysis.")
    if selected_model != AIProvider.GEMINI.value:
        msg = f"⚠️ Model '{html.escape(selected_model)}' not supported."
        return {
            out_status: gr.update(value=msg), out_download: gr.update(visible=False),
            out_file_results: gr.update(value=f"<p style='color: orange;'>{msg} Please select '{AIProvider.GEMINI.value}'.</p>"),
            out_processing_log: gr.update(value="")
        }
    try:
        genai.configure(api_key=API_KEYS[current_key_index]);
        model = genai.GenerativeModel("models/gemini-1.5-flash-latest")
        print(f"Using Gemini model: 'gemini-1.5-flash-latest' with API key index {current_key_index}")
    except Exception as e:
        msg = f"🚨 Failed to initialize AI Model: {html.escape(str(e))}"
        return {
            out_status: gr.update(value=msg), out_download: gr.update(visible=False),
            out_file_results: gr.update(value=f"<p style='color: red;'>{msg}</p>"),
            out_processing_log: gr.update(value="")
        }
    # --- End Initial Checks ---

    analysis_results = [];
    pdf_files_generated = [];
    error_count = 0;
    success_count = 0
    # Initialize summary_log here
    summary_log = f"📊 Analysis started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} for {total_files} file(s)\n🤖 Model: {selected_model}\n⚠️ Reports auto-delete after 24h.\n\n"

    for i, file_obj in enumerate(progress.tqdm(files, desc="Analyzing Files")):
        file_path = Path(file_obj.name) if hasattr(file_obj, 'name') else Path(str(file_obj))
        file_name_display = file_path.name
        current_file_log_prefix = f"📄 File {i + 1}/{total_files} ('{file_name_display}'):"
        print(f"\n--- {current_file_log_prefix} ---")
        file_result = {"filename": file_name_display, "status": "Processing", "details": "", "json_data": None}

        # --- Append processing steps to summary_log ---
        summary_log += f"--- {current_file_log_prefix} ---\n"

        content = extract_content(str(file_path))
        if isinstance(content, str) and (
                content.startswith("❌") or content.startswith("📄") or content.startswith("📊")):
            file_result["status"] = "❌ Extraction Error";
            file_result["details"] = content
            summary_log += f"Extraction Failed: {content}\n"  # Add to log
            analysis_results.append(file_result);
            error_count += 1
            print(f"{current_file_log_prefix} Failed extraction: {content}");
            continue
        else:
            summary_log += f"Content extracted successfully (Length: {len(content)}).\n"  # Add success to log

        prompt = build_prompt(content)
        summary_log += "Sending request to AI...\n"  # Add to log
        try:
            response = safe_gener
