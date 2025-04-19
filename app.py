# -*- coding: utf-8 -*-
import gradio as gr
import os
import fitz
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
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables from .env
load_dotenv()

# Optional: Print CWD for debugging deployment environments
try:
    print(f"Current working directory: {os.getcwd()}")
    print(f"Files in CWD: {os.listdir('.')}")
    print(f"Contents of 'analyzed_reports': {os.listdir('analyzed_reports') if os.path.exists('analyzed_reports') else 'Directory not found'}")
    print(f"Contents of 'fonts': {os.listdir('fonts') if os.path.exists('fonts') else 'Directory not found'}")
except Exception as e:
    print(f"Could not list directory contents: {e}")


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
    OPENAI = "OpenAI" # Placeholder for future
    CLAUDE = "Claude" # Placeholder for future
    DEEPSEEK = "DeepSeek" # Placeholder for future

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
            if not text.strip(): return "📄 PDF contained no extractable text."
            print(f"Successfully extracted text from PDF '{file_name}'. Length: {len(text)}")
            return text
        elif ext in [".xls", ".xlsx"]:
            xls = pd.ExcelFile(file_path)
            all_sheets_text = []
            if not xls.sheet_names: return "📊 Excel file seems empty or has no sheets."
            for sheet_name in xls.sheet_names:
                try:
                    df = pd.read_excel(xls, sheet_name=sheet_name)
                    if not df.empty: all_sheets_text.append(f"--- Sheet: {sheet_name} ---\n{df.to_string()}\n")
                    else: all_sheets_text.append(f"--- Sheet: {sheet_name} (empty) ---\n")
                except Exception as sheet_err: all_sheets_text.append(f"--- Sheet: {sheet_name} (Error reading: {sheet_err}) ---\n")
            if not all_sheets_text: return "📊 Excel file contained no data in readable sheets."
            full_text = "\n".join(all_sheets_text)
            print(f"Successfully extracted data from Excel '{file_name}'. Length: {len(full_text)}")
            return full_text
        elif ext in [".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".md", ".rtf"]:
            encodings_to_try = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
            content = None
            for encoding in encodings_to_try:
                try:
                    with open(Path(file_path), 'r', encoding=encoding) as f: content = f.read()
                    print(f"Successfully read '{file_name}' with encoding '{encoding}'. Length: {len(content)}")
                    return content
                except UnicodeDecodeError: continue
                except Exception as read_err: return f"❌ Error reading file '{file_name}': {read_err}"
            return f"❌ Error reading file: Could not decode '{file_name}' using tried encodings."
        else: return f"❌ Unsupported file format: {ext}"
    except fitz.FileNotFoundError: return f"❌ Error: File not found '{file_name}'"
    except Exception as e: print(f"🚨 Unexpected error reading file '{file_name}': {e}"); return f"❌ Unexpected error reading file '{file_name}': {e}"

def build_prompt(content):
    """Creates the prompt for the Gemini model."""
    max_prompt_content_length = 25000
    truncated_content = content[:max_prompt_content_length]
    if len(content) > max_prompt_content_length: truncated_content += "\n\n[CONTENT TRUNCATED DUE TO LENGTH]"
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
    if not response_text: raise ValueError("Received empty response text from AI.")
    cleaned_text = response_text.strip()
    print(f"Attempting to extract JSON from response (first 500 chars): {cleaned_text[:500]}")
    cleaned_text = re.sub(r'^```json\s*', '', cleaned_text, flags=re.IGNORECASE | re.DOTALL)
    cleaned_text = re.sub(r'\s*```\s*$', '', cleaned_text, flags= re.DOTALL)
    cleaned_text = cleaned_text.strip()
    if not cleaned_text.startswith('{') or not cleaned_text.endswith('}'):
        start_index = cleaned_text.find('{'); end_index = cleaned_text.rfind('}')
        if (start_index != -1 and end_index != -1 and end_index > start_index):
            json_str = cleaned_text[start_index : end_index + 1]; print("Warning: Extracted JSON content.")
        else: raise json.JSONDecodeError(f"No valid JSON object structure found. Start: {cleaned_text[:200]}...", cleaned_text, 0)
    else: json_str = cleaned_text
    try:
        parsed_json = json.loads(json_str); print("Successfully parsed JSON."); return parsed_json
    except json.JSONDecodeError as e:
        error_pos_context = json_str[max(0, e.pos-20):min(len(json_str), e.pos+20)]
        print(f"🚨 JSON Decode Error: {e.msg} near '{error_pos_context}'."); raise json.JSONDecodeError(f"Failed to decode JSON: {e.msg} near '{error_pos_context}'", json_str, e.pos) from e

def generate_pdf_report(file_name, json_data):
    """Generate a PDF report."""
    logger.info("--- ENTERING generate_pdf_report FUNCTION ---")
    pdf = None; output_path = None
    # Define font file paths. Ensure these files are in the same directory as app.py
    # or in a 'fonts' subdirectory. Adjust as needed for your deployment.
    font_path = 'DejaVuSansCondensed.ttf'
    font_path_bold = 'DejaVuSansCondensed-Bold.ttf'
    fonts_dir = 'fonts' # Optional subdirectory

    logger.info(f"[PDF START] Starting PDF generation for: {file_name}") # Explicit start log

    def check_font_path(path):
        exists = os.path.exists(path)
        logger.info(f"[PDF CHECK] Font path: {path}, exists: {exists}")
        return exists

    # try:
      #  found_regular = check_font_path(font_path) or check_font_path(os.path.join(fonts_dir, font_path))
      #  found_bold = check_font_path(font_path_bold) or check_font_path(os.path.join(fonts_dir, font_path_bold))

      #  if not found_regular or not found_bold:
        #    error_message = f"🚨 [PDF ERROR] Font files not found. Ensure '{font_path}' and '{font_path_bold}' are alongside app.py or in a '{fonts_dir}' subdirectory."
         #   logger.error(error_message)
          #  raise FileNotFoundError(error_message)

        pdf = FPDF()
        logger.info("[PDF INIT] FPDF initialized.") # Log after initialization
      #  try:
       #     pdf.add_font('DejaVu', '', font_path if os.path.exists(font_path) else os.path.join(fonts_dir, font_path))
        #    logger.info("[PDF FONT] DejaVu regular added.") # Log after adding font
        #except Exception as e:
         #   logger.error(f"🚨 [PDF ERROR] Error adding regular font: {e}", exc_info=True)
          #  raise

        #try:
         #   pdf.add_font('DejaVu', 'B', font_path_bold if os.path.exists(font_path_bold) else os.path.join(fonts_dir, font_path_bold))
          #  logger.info("[PDF FONT] DejaVu bold added.") # Log after adding font
       # except Exception as e:
        #    logger.error(f"🚨 [PDF ERROR] Error adding bold font: {e}", exc_info=True)
         #   raise

        pdf.add_page()
        logger.info("[PDF PAGE] Page added.") # Log after adding page
        pdf.set_margins(15, 15, 15)
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(w=0, h=10, text="Cybersecurity Threat Analysis Report", align='C', new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Arial", '', 11)
        safe_display_name = html.escape(file_name.encode('latin-1', 'replace').decode('latin-1'))
        pdf.cell(w=0, h=8, text=f"Log File Analyzed: {safe_display_name}", align='C', new_x="LMARGIN", new_y="NEXT")
        pdf.ln(8)
        pdf.set_font("Arial", 'B', 13)
        pdf.cell(w=0, h=8, text="Analysis Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(4)
        report_fields = {"Threat Level": json_data.get("threat_level", "N/A"), "Risk Score": str(json_data.get("risk_score", "N/A")), "Detected Threat / Event": json_data.get("detected_threat_type", "N/A"), "Affected System / Entity": json_data.get("affected_system", "N/A"), "Event Summary": json_data.get("summary", "N/A"), "MITRE ATT&CK Mapping": json_data.get("mitre_mapping", []), "Recommended Actions": json_data.get("recommended_actions", [])}
        field_label_width = 60
        value_start_x = 15 + field_label_width + 2
        for key, value in report_fields.items():
            current_y = pdf.get_y()
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(w=field_label_width, h=7, text=f"{key}:")
            pdf.set_font("Arial", '', 11)
            pdf.set_xy(value_start_x, current_y)
            available_width = pdf.w - value_start_x - pdf.r_margin
            if isinstance(value, list):
                if value:
                    first_item = True
                    for item in value:
                        if not first_item:
                            pdf.set_x(value_start_x)
                        safe_item = str(item).encode('latin-1', 'replace').decode('latin-1')
                        pdf.multi_cell(w=available_width, h=7, text=f"• {safe_item}")
                        first_item = False
                else:
                    pdf.multi_cell(w=available_width, h=7, text="N/A")
            else:
                safe_value = str(value).encode('latin-1', 'replace').decode('latin-1')
                pdf.multi_cell(w=available_width, h=7, text=safe_value)

            pdf.set_x(15)
            if pdf.get_y() < current_y + 7:
                pdf.set_y(current_y + 7)
            pdf.ln(3)

        pdf.ln(10)
        pdf.set_font("Arial", '', 9)
        pdf.set_text_color(128, 128, 128)
        pdf.cell(w=0, h=10, text=f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} using Gemini AI", align='C', new_x="LMARGIN", new_y="NEXT")
        safe_file_stem = re.sub(r'[\\/*?:"<>|]', "_", Path(file_name).stem)
        timestamp_suffix = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_filename = f"{safe_file_stem}_report_{timestamp_suffix}.pdf"
        output_path = Path(REPORTS_DIR) / output_filename

        logger.info(f"[PDF SAVE] Attempting to create reports directory: {REPORTS_DIR}")
        try:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            logger.info(f"[PDF SAVE] Directory check/create successful for: {REPORTS_DIR}")
        except Exception as mkdir_err:
            logger.error(f"🚨 [PDF ERROR] Failed to create directory {REPORTS_DIR}: {mkdir_err}", exc_info=True)
            return None # Exit if directory fails

        logger.info(f"[PDF SAVE] Attempting to save PDF to: {output_path}")
        try:
            pdf.output(str(output_path))
            logger.info(f"[PDF SAVE] PDF output command completed. Checking if file exists: {output_path.exists()}")
            if not output_path.exists():
                error_message = f"🚨 [PDF ERROR] Failed to create PDF file at {output_path} after pdf.output() call."
                logger.error(error_message)
                raise FileNotFoundError(error_message)
        except Exception as pdf_save_err:
            logger.error(f"🚨 [PDF ERROR] pdf.output() failed: {pdf_save_err}", exc_info=True)
            return None # Exit if saving fails

        logger.info(f"✅ [PDF END] Successfully generated PDF report: {output_path}")
        return str(output_path)
   # except FileNotFoundError as fnf_err: # Specifically catch font or post-save check errors
    #    logger.error(f"🚨 [PDF ERROR] (FileNotFound): {fnf_err}", exc_info=True)
     #   return None
    except Exception as e:
        logger.error(f"🚨 [PDF ERROR] (General Exception during PDF generation): {e}", exc_info=True)
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
                    # Accessing finish_reason and safety_ratings might give more details
                    finish_reason = response.prompt_feedback.block_reason.name if response.prompt_feedback and response.prompt_feedback.block_reason else "Unknown"
                    safety_ratings = response.prompt_feedback.safety_ratings if response.prompt_feedback else []
                    block_reason = f"Finish Reason: {finish_reason}, Safety Ratings: {safety_ratings}"
                except Exception as feedback_err:
                    print(f"Error retrieving block reason details: {feedback_err}")
                    pass # Use default block_reason
                raise Exception(f"🛑 Content generation blocked. Reason: {block_reason}")

            if hasattr(response, 'text') and response.text:
                print(f"🎯 Success with key #{current_key_index + 1}")
                return response

            # If no text but also not blocked, it's an unexpected state
            finish_reason_detail = "Unknown"
            try:
                finish_reason_detail = response.candidates[0].finish_reason.name if response.candidates and response.candidates[0].finish_reason else "Not Available"
            except Exception: pass
            raise Exception(f"Generation succeeded but unexpected response format (no text). Finish Reason: {finish_reason_detail}")


        except Exception as e:
            error_str = str(e).lower()
            print(f"🚨 Error with key #{current_key_index + 1}: {e}")

            is_quota_error = any(term in error_str for term in ["quota", "429", "resource has been exhausted"])
            is_auth_error = any(term in error_str for term in ["permission denied", "api key not valid", "api key invalid", "401", "403", "invalid api key"])
            is_safety_block = "blocked" in error_str # Broader check for safety blocks

            if is_safety_block:
                raise e # Don't retry safety blocks, raise immediately
            elif is_quota_error or is_auth_error:
                # Rotate to next key
                current_key_index = (current_key_index + 1) % len(API_KEYS)
                if current_key_index == initial_key_index and attempt > 0: # Cycled through all keys
                    raise Exception(f"🔁 All API keys exhausted or failed ({len(API_KEYS)} keys tried). Last error: {e}") from e
                print(f"🔃 Switching to backup key #{current_key_index + 1}...")
                time.sleep(2) # Brief pause before retrying with new key
                continue # Continue to next attempt in the loop
            else: # Other errors (network, internal server, etc.)
                # Could implement more specific retry logic here if needed
                # For now, re-raise if not quota/auth/safety
                raise e # Re-raise unexpected errors

    raise Exception(f"❌ Failed after {max_retries} attempts with {len(API_KEYS)} key(s).")

def cleanup_old_reports():
    """Delete old reports."""
    now = time.time(); cutoff = now - (24 * 60 * 60); count = 0
    print(f"🧹 Starting cleanup of old reports in '{REPORTS_DIR}'...")
    try:
        if not os.path.isdir(REPORTS_DIR): print("    Info: Reports directory does not exist."); return
        for filename in os.listdir(REPORTS_DIR):
            if filename.lower().endswith((".pdf", ".zip")):
                file_path = os.path.join(REPORTS_DIR, filename)
                try:
                    if os.path.isfile(file_path) and os.path.getmtime(file_path) < cutoff:
                        os.remove(file_path); print(f"    - Deleted old report: {filename}"); count += 1
                except Exception as e: print(f"    - ⚠️ Error processing/deleting {filename}: {e}")
        if count > 0: print(f"🧹 Cleanup finished. Deleted {count} old report file(s).")
        else: print("🧹 No old report files found matching criteria for deletion.")
    except Exception as e: print(f"🚨 Error during cleanup: {e}")

def analyze_multiple_files(files, selected_model, progress=gr.Progress(track_tqdm=True)):
    """Analyze multiple files and generate report/log."""
    start_time = time.time()
    if files is None: files = []
    elif not isinstance(files, list): files = [files]

    # --- Initial checks return explicit updates ---
    if not files:
        return {
            out_status: gr.update(value="❌ No files uploaded."),
            out_download: gr.update(visible=False),
            out_file_results: gr.update(value="<p style='color: orange;'>Please upload at least one file.</p>"),
            out_processing_log: gr.update(value="")
        }
    total_files = len(files); print(f"Received {total_files} file(s) for analysis.")
    if selected_model != AIProvider.GEMINI.value:
        msg = f"⚠️ Model '{html.escape(selected_model)}' not supported."
        return {
            out_status: gr.update(value=msg), out_download: gr.update(visible=False),
            out_file_results: gr.update(value=f"<p style='color: orange;'>{msg} Please select '{AIProvider.GEMINI.value}'.</p>"), out_processing_log: gr.update(value="")
        }
    try:
        # Configure with the current key, safe_generate_content will handle rotation
        genai.configure(api_key=API_KEYS[current_key_index]); model = genai.GenerativeModel("models/gemini-1.5-flash-latest")
        print(f"Using Gemini model: 'gemini-1.5-flash-latest' with initial API key index {current_key_index}")
    except Exception as e:
        msg = f"🚨 Failed to initialize AI Model: {html.escape(str(e))}"
        return {
            out_status: gr.update(value=msg), out_download: gr.update(visible=False),
            out_file_results: gr.update(value=f"<p style='color: red;'>{msg}</p>"), out_processing_log: gr.update(value="")
        }
    # --- End Initial Checks ---

    analysis_results = []; pdf_files_generated = [];
    # Initialize summary_log here
    summary_log = f"📊 Analysis started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} for {total_files} file(s)\n🤖 Model: {selected_model}\n⚠️ Reports auto-delete after 24h.\n\n"

    for i, file_obj in enumerate(progress.tqdm(files, desc="Analyzing Files")):
        file_path = Path(file_obj.name) if hasattr(file_obj, 'name') else Path(str(file_obj))
        file_name_display = file_path.name
        current_file_log_prefix = f"📄 File {i+1}/{total_files} ('{file_name_display}'):"
        print(f"\n--- {current_file_log_prefix} ---")
        # Initialize file_result with 'Processing' status
        file_result = {"filename": file_name_display, "status": "Processing", "details": "", "json_data": None}

        # --- Append processing steps to summary_log ---
        summary_log += f"--- {current_file_log_prefix} ---\n"

        content = extract_content(str(file_path))
        if isinstance(content, str) and (content.startswith("❌") or content.startswith("📄") or content.startswith("📊")):
            file_result["status"] = "❌ Extraction Error"; file_result["details"] = content
            summary_log += f"Extraction Failed: {content}\n\n" # Add to log and add newline
            analysis_results.append(file_result)
            print(f"{current_file_log_prefix} Failed extraction: {content}"); continue # Skip to next file
        else:
            summary_log += f"Content extracted successfully (Length: {len(content)}).\n" # Add success to log

        prompt = build_prompt(content)
        summary_log += "Sending request to AI...\n" # Add to log
        try:
            response = safe_generate_content(model, prompt); raw_text = response.text
            summary_log += f"Received response from AI.\n" # Add to log
            try:
                json_data = parse_json_response(raw_text); file_result["json_data"] = json_data
                print(f"{current_file_log_prefix} Successfully parsed JSON.")
                summary_log += "Successfully parsed JSON response.\n" # Add to log

                print("🐞 About to call generate_pdf_report")
                pdf_file_path = generate_pdf_report(file_name_display, json_data)
                if pdf_file_path:
                    pdf_files_generated.append(pdf_file_path); file_result["status"] = "✅ Success"
                    try: file_result["details"] = json.dumps(json_data, indent=2) # Store formatted JSON in details for success
                    except Exception: file_result["details"] = "Analyzed, failed to format JSON for display."
                    summary_log += f"✅ PDF generated: {Path(pdf_file_path).name}\n";
                else:
                    file_result["status"] = "⚠️ Analysis OK, PDF Failed"; file_result["details"] = "PDF generation failed. Check application logs for details (e.g., missing fonts)."
                    summary_log += f"⚠️ PDF generation failed.\n";
            except json.JSONDecodeError as je:
                error_detail = f"JSON Error: {je}. Start: '{html.escape(raw_text[:150])}...'";
                file_result["status"] = "❌ JSON Parsing Error"; file_result["details"] = error_detail
                summary_log += f"❌ JSON Parsing Error: {je}\n"; print(f"🚨 {current_file_log_prefix} JSON Error: {je}")
            except ValueError as ve: # Catch empty AI response from parse_json_response
                file_result["status"] = "❌ AI Response Error"; file_result["details"] = f"AI Error: {ve}"; summary_log += f"❌ AI Error: {ve}\n"; print(f"🚨 {current_file_log_prefix} AI Error: {ve}")

        except Exception as analysis_err: # Catch API errors from safe_generate_content, safety blocks etc.
            file_result["status"] = "❌ AI Analysis Error"; file_result["details"] = f"Analysis Error: {analysis_err}"; summary_log += f"❌ Analysis Error: {analysis_err}\n"; print(f"🚨 {current_file_log_prefix} Analysis Error: {analysis_err}")

        # Append the result for this file
        analysis_results.append(file_result)
        summary_log += "\n" # Add space between file logs in summary

    # --- Finalizing ---
    print("\n--- Finalizing Analysis Results ---"); zip_path = None; final_status_message = ""; end_time = time.time(); duration = round(end_time - start_time, 2)

    if pdf_files_generated: # Only try zipping if PDFs were actually created
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S"); zip_filename = f"Threat_Analysis_Reports_{timestamp}.zip"; zip_path = os.path.join(REPORTS_DIR, zip_filename)
        print(f"Creating ZIP: {zip_path} ({len(pdf_files_generated)} PDFs)")
        summary_log += f"Attempting to create ZIP: {zip_filename}\n" # Add to log
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for pdf_file in progress.tqdm(pdf_files_generated, desc="Zipping"):
                    pdf_basename = os.path.basename(pdf_file)
                    try:
                        if os.path.exists(pdf_file): zipf.write(pdf_file, arcname=pdf_basename); summary_log += f"  + Added '{pdf_basename}'\n"
                        else: print(f"  - Warning: PDF not found for zipping '{pdf_basename}'."); summary_log += f"  - PDF not found: '{pdf_basename}'\n"
                    except Exception as zip_err: print(f"  - ⚠️ Error adding '{pdf_basename}': {zip_err}"); summary_log += f"  - Error adding '{pdf_basename}': {zip_err}\n"
            print(f"Successfully created ZIP: {zip_path}"); summary_log += f"Successfully created ZIP: {zip_filename}\n"
            removed_pdf_count = 0
            summary_log += f"Removing individual PDFs...\n"
            for pdf_file in pdf_files_generated:
                try:
                    if os.path.exists(pdf_file): os.remove(pdf_file); removed_pdf_count += 1
                except OSError as remove_err: print(f"⚠️ Could not remove '{os.path.basename(pdf_file)}': {remove_err}"); summary_log += f"  - Error removing '{os.path.basename(pdf_file)}': {remove_err}\n"
            print(f"Removed {removed_pdf_count} individual PDF(s)."); summary_log += f"Removed {removed_pdf_count} individual PDF(s).\n"
        except Exception as e:
            print(f"🚨 Error creating or cleaning up ZIP: {e}")
            summary_log += f"\n🚨 Error creating or cleaning up ZIP: {e}\n"
            # Decide if we should nullify zip_path if zipping fails critically
            zip_path = None # Set zip_path to None if zipping failed


    # *** Start Patched Section: Revised Final Status Logic ***
    num_total = len(analysis_results)
    num_success = sum(1 for r in analysis_results if r["status"] == "✅ Success")
    num_pdf_failed = sum(1 for r in analysis_results if r["status"] == "⚠️ Analysis OK, PDF Failed")
    num_errors = sum(1 for r in analysis_results if "❌" in r["status"]) # Any status containing 'Error'

    zip_status_text = "ZIP created." if zip_path else "No reports generated or ZIP failed."

    if num_errors == num_total and num_total > 0:
        final_status_message = f"❌ Analysis Failed ({duration}s) for all {num_total} files due to errors."
    elif num_success + num_pdf_failed == num_total and num_total > 0: # All files processed by AI at least
        if num_pdf_failed == 0:
            final_status_message = f"✅ Analysis Complete ({duration}s). {num_success}/{num_total} succeeded. {zip_status_text}"
        else:
            final_status_message = f"⚠️ Analysis Complete ({duration}s). {num_success}/{num_total} fully succeeded, {num_pdf_failed} had PDF errors. {zip_status_text}"
    elif num_total > 0 : # Mixed results or other combinations
        final_status_message = f"ℹ️ Analysis Partially Complete ({duration}s). {num_success} success, {num_pdf_failed} PDF fail, {num_errors} errors. {zip_status_text}"
    else: # No files processed (should have been caught earlier, but as fallback)
        final_status_message = f"ℹ️ Analysis finished ({duration}s). No files processed."
    # *** End Patched Section ***

    # --- Generate HTML Outputs ---
    # 1. File Results HTML (for direct display)
    file_results_html = "<h3>Analysis Results per File</h3>"
    if not analysis_results: file_results_html += "<p>No files processed or results available.</p>"
    else:
        file_results_html += "<div class='results-container'>"
        for result in analysis_results:
            status_class = "status-success" if "✅ Success" in result["status"] else ("status-warning" if "⚠️" in result["status"] else "status-danger")
            border_color = "var(--success-border-color)" if "✅ Success" in result["status"] else ("var(--warning-border-color)" if "⚠️" in result["status"] else "var(--danger-border-color)")
            escaped_filename = html.escape(result.get('filename', 'Unknown')); escaped_status = html.escape(result.get('status', 'N/A'))
            escaped_details = html.escape(result.get('details', 'N/A')) # Contains formatted JSON on success, error message otherwise

            file_results_html += f"<div class='threat-box {status_class}' style='border-left-color: {border_color};'>"
            file_results_html += f"<h4>📄 {escaped_filename} &nbsp;|&nbsp; <span class='status-text'>{escaped_status}</span></h4>" # Use &nbsp; for spacing
            # Display JSON pre for success, otherwise display details as paragraph
            if result.get("status") == "✅ Success":
                file_results_html += f"<pre class='json-output'>{escaped_details}</pre>" # Show JSON
            elif result.get("details"):
                # Add specific class for errors/warnings if needed
                detail_class = "error-details" if "❌" in result["status"] else "warning-details"
                file_results_html += f"<p class='{detail_class}'>{escaped_details}</p>" # Show error/warning details
            else: file_results_html += "<p>No details provided.</p>" # Fallback
            file_results_html += "</div>"
        file_results_html += "</div>"

    # 2. Processing Log HTML (for accordion)
    summary_log += f"\n🏁 Analysis finished in {duration} seconds. Final Status: {final_status_message}\n" # Add final status to log
    processing_log_html = f"<pre class='processing-log'>{html.escape(summary_log)}</pre>"
    # --- End HTML Generation ---

    print(f"--- Analysis Complete. Status: {final_status_message} ---")
    # Return dictionary mapping components to updates
    return {
        out_status: gr.update(value=final_status_message),
        out_download: gr.update(value=zip_path, visible=bool(zip_path)),
        out_file_results: gr.update(value=file_results_html), # Update component for per-file results
        out_processing_log: gr.update(value=processing_log_html) # Update component in accordion
    }

def chatbot_reply(message, history):
    """Generate chatbot reply."""
    msg_lower = message.lower().strip(); reply = ""
    print(f"Chatbot received: '{message}'")
    if any(word in msg_lower for word in ["support", "contact"]): reply = "For support, please refer to the Contact link in the header or reach out to the developer (Ajmal Malayil)."
    elif "mitre" in msg_lower or "att&ck" in msg_lower: reply = "MITRE ATT&CK® is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The report attempts to map findings to relevant technique IDs (e.g., T1059.001 for PowerShell execution)."
    elif "threat level" in msg_lower: reply = "Threat Level indicates the assessed severity: INFO (Informational), LOW (Minor issue, monitor), MEDIUM (Potential threat, investigation recommended), HIGH (Likely threat, requires prompt attention), CRITICAL (Active compromise or severe vulnerability, immediate action required), N/A (Not Applicable or Undetermined)."
    elif "risk score" in msg_lower: reply = "Risk Score is an estimated numerical representation (0-100) of the risk, considering the threat level and context. Higher scores indicate greater risk. It's 0 for INFO or N/A levels."
    elif any(word in msg_lower for word in ["safe", "privacy", "store", "keep files"]): reply = "Uploaded files are processed in memory for analysis. Generated PDF/ZIP reports are stored temporarily in the 'analyzed_reports' directory and are automatically deleted after 24 hours by the cleanup routine. Original uploaded files are not stored long-term on the server after processing."
    elif any(model.value.lower() in msg_lower for model in AIProvider if model != AIProvider.GEMINI): reply = f"Currently, only the {AIProvider.GEMINI.value} model is implemented and supported for analysis."
    elif any(word in msg_lower for word in ["how", "work", "steps", "process"]): reply = "The process is: 1. You upload log files (PDF, Excel, text...). 2. The tool extracts text content. 3. The extracted text is sent to the Gemini AI with specific instructions to analyze for threats. 4. The AI returns a structured JSON analysis. 5. A PDF report is generated from the JSON data. 6. If multiple reports are generated, they are zipped for download."
    elif any(greet in msg_lower for greet in ["hi", "hello", "hey"]): reply = "Hello! I'm LogBot, your assistant for this Threat Analyzer. How can I help you understand the tool or the analysis results?"
    elif any(bye in msg_lower for bye in ["bye", "thanks", "thank you", "ok"]): reply = "You're welcome! Let me know if anything else comes up."
    elif "font" in msg_lower and "error" in msg_lower: reply = "A common reason for PDF generation failure is missing 'DejaVuSansCondensed' fonts. Ensure they are placed correctly alongside the application script in the deployment environment."
    else: reply = "I can help explain terms found in the report (like 'Threat Level', 'Risk Score', 'MITRE Mapping'), how the tool works, or common issues. What would you like to know?"
    print(f"Chatbot replying: '{reply}'"); return reply

def clear_outputs():
    """Returns updates dictionary to clear outputs."""
    print("Clearing outputs...")
    cleanup_old_reports() # Run cleanup when clearing
    # Return dictionary mapping components to updates
    return {
        out_status: gr.update(value=""),
        out_download: gr.update(value=None, visible=False),
        out_file_results: gr.update(value=""), # Clear file results HTML
        out_processing_log: gr.update(value="") # Clear processing log HTML
    }


# --------------------------------------------------------------------------
# Gradio Interface Setup
# --------------------------------------------------------------------------
css = """
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f8f9fa; }
#top-bar { background-color: #343a40; color: white; padding: 10px 25px; }
#top-bar-content { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: auto; }
#top-bar h1 { font-size: 1.5em; margin: 0; }
#top-bar a { color: #adb5bd; text-decoration: none; margin-left: 15px; }
#top-bar a:hover { color: white; }
.main-content { max-width: 1000px; margin: 20px auto; padding: 0 15px; }
.upload-box, .results-box, .section-header { margin-bottom: 20px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.gradio-file { border: 2px dashed #ced4da; border-radius: 5px; padding: 15px; }
.button-primary { /* styles for primary button if needed */ }
.status-text > label > span { font-weight: bold; }
.status-text textarea { font-size: 1.1em; font-weight: 500; }
.gradio-accordion { border: 1px solid #dee2e6; border-radius: 5px; margin-top: 15px; }
.output-html h3 { margin-top: 0px; margin-bottom: 10px; color: #495057; border-bottom: 1px solid #e9ecef; padding-bottom: 5px; }
/* Style for Processing Log Pre */
.processing-log { background-color: #f1f3f5; padding: 10px; border-radius: 4px; font-family: 'Consolas', 'Monaco', monospace; white-space: pre-wrap; word-wrap: break-word; margin-bottom: 10px; color: #495057; font-size: 0.9em; max-height: 400px; overflow-y: auto; border: 1px solid #ced4da; }
.results-container { margin-top: 15px; }
.threat-box { padding: 15px; margin-bottom: 15px; border-radius: 5px; border-left: 5px solid #6c757d; background-color: #ffffff; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
.threat-box h4 { margin-top: 0; margin-bottom: 10px; font-size: 1.1em; display: flex; align-items: center; color: #343a40;}
.threat-box h4 > span.status-text { font-weight: bold; margin-left: auto; font-size: 0.95em; padding: 3px 8px; border-radius: 4px; }
:root { --success-border-color: #28a745; --success-bg-color: #e9f7ec; --success-text-color: #28a745; --warning-border-color: #ffc107; --warning-bg-color: #fff8e1; --warning-text-color: #b98900; --danger-border-color: #dc3545; --danger-bg-color: #f8d7da; --danger-text-color: #dc3545; }
.status-success { border-left-color: var(--success-border-color) !important; background-color: var(--success-bg-color); }
.status-success h4 > span.status-text { background-color: var(--success-text-color); color: white; }
.status-warning { border-left-color: var(--warning-border-color) !important; background-color: var(--warning-bg-color); }
.status-warning h4 > span.status-text { background-color: var(--warning-text-color); color: white; }
.status-danger { border-left-color: var(--danger-border-color) !important; background-color: var(--danger-bg-color); }
.status-danger h4 > span.status-text { background-color: var(--danger-text-color); color: white; }
/* Style for JSON output within threat box */
.json-output { border: 1px solid #e0e0e0; background-color: #fdfdfd; color: #333; padding: 10px; border-radius: 4px; font-family: 'Consolas', 'Monaco', monospace; white-space: pre-wrap; word-wrap: break-word; font-size: 0.9em; margin-top: 10px; }
/* Style for error/warning details within threat box */
.error-details, .warning-details { padding: 10px; border-radius: 4px; font-family: 'Consolas', 'Monaco', monospace; white-space: pre-wrap; word-wrap: break-word; font-size: 0.9em; margin-top: 10px; }
.error-details { color: var(--danger-text-color); background-color: #fef4f5; border: 1px solid var(--danger-border-color);}
.warning-details { color: var(--warning-text-color); background-color: #fffbf0; border: 1px solid var(--warning-border-color); }
#chat-button { position: fixed; bottom: 25px; right: 25px; z-index: 1001; width: 55px; height: 55px; border-radius: 50%; background-color: var(--primary-500); color: white; font-size: 1.8em; border: none; cursor: pointer; box-shadow: 0 2px 5px rgba(0,0,0,0.2); display: flex; align-items: center; justify-content: center; transition: background-color 0.2s ease; }
#chat-button:hover { background-color: var(--primary-600); }
#chat-container { visibility: hidden; opacity: 0; position: fixed; bottom: 90px; right: 25px; width: 380px; max-width: 90vw; z-index: 1000; background: white; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.15); transition: opacity 0.3s ease, visibility 0.3s ease; overflow: hidden; }
#chat-container.visible { visibility: visible; opacity: 1; }
.footer { text-align: center; padding: 20px; margin-top: 30px; color: #6c757d; font-size: 0.9em; border-top: 1px solid #dee2e6; }
.footer b { color: #495057; }
"""

# Define components within Blocks context BEFORE using them in handlers
with gr.Blocks(css=css, theme=gr.themes.Soft()) as demo:
    with gr.Row(elem_id="top-bar"):
        gr.HTML("""
        <div id="top-bar-content">
            <h1>🛡️ Enterprise Threat Analyzer Pro</h1>
            <div>
                <a href='https://ajmalmalayil.pages.dev/' target='_blank'>🌐 Portfolio</a>
                <a href='https://wa.me/+971544566442' target='_blank'>💬 Contact</a>
            </div>
        </div>
        """) # Placeholder links

    with gr.Column(elem_classes="main-content"):
        gr.Markdown("""
        ## AI-Powered Log Analysis for Security Insights
        Upload log files (text, PDF, Excel) to identify potential threats, assess risks, and get recommended actions using Google's Gemini AI.
        """)
        gr.Markdown("<span style='color:var(--danger-text-color, #dc3545); font-weight:600;'>⚠️ Security & Privacy:</span> Reports are auto-deleted after 24 hours. Uploaded files aren't stored long-term.",
                    elem_id="privacy-note")

        with gr.Column(elem_classes="upload-box"):
            gr.Markdown("### 1. Upload Files & Configure")
            with gr.Row():
                files = gr.File(label="📁 Select Log Files", file_types=[".txt", ".log", ".pdf", ".xlsx", ".xls", ".csv", ".json", ".xml", ".yaml", ".md", ".rtf"], file_count="multiple", scale=3)
                with gr.Column(scale=1, min_width=180):
                    selected_model = gr.Radio(choices=[m.value for m in AIProvider], label="🤖 AI Model", value=AIProvider.GEMINI.value)
                    analyze_btn = gr.Button("🔍 Analyze Threats", variant="primary") # Use variant

        # --- Define Output Components ---
        with gr.Column(elem_classes="results-box"):
            gr.Markdown("### 2. Analysis Status & Results", elem_classes="section-header")
            out_status = gr.Textbox(label="📊 Overall Status", lines=1, interactive=False, placeholder="Analysis status will appear here...") # Improved placeholder
            out_download = gr.File(label="📦 Download Report ZIP", interactive=False, visible=False)
            # Component for per-file results (directly visible)
            out_file_results = gr.HTML(label="File Analysis Details", value="<p>Results per file will appear here after analysis.</p>") # Initial placeholder
            # Accordion for processing log only
            with gr.Accordion("📋 View Processing Log", open=False):
                out_processing_log = gr.HTML(value="<p>Detailed processing steps will appear here...</p>") # Initial placeholder

        # --- Define Chat Components ---
        with gr.Column(elem_id="chat-container") as chat_section: # Initially hidden
            chat_interface = gr.ChatInterface(
                fn=chatbot_reply,
                chatbot=gr.Chatbot(label="💬 Chat with LogBot", height=400, show_copy_button=True, avatar_images=(None, "https://img.icons8.com/color/48/bot.png")), # Ensure type is inferred or set if needed
                textbox=gr.Textbox(placeholder="Ask about the tool, results, terms...", container=False, scale=7),
                theme="soft",
                # Removed explicit type="messages" as Chatbot defines its structure
                # examples = ["Explain Threat Level", "What is MITRE?", "Why did PDF fail?", "How does it work?"] # Add examples if desired
            )
        chat_btn = gr.Button("💬", elem_id="chat-button")

        # --- Define Event Handlers (AFTER components are defined) ---
        # Define the list of output components - MUST match the variables used below
        analysis_outputs = [out_status, out_download, out_file_results, out_processing_log]

        # Make sure the variables passed to outputs= in the clicks match the component variables
        analyze_btn.click(
            fn=clear_outputs, # Step 1: Clear outputs
            inputs=None,
            outputs=analysis_outputs, # Clear these components
            queue=False # Run clear immediately
        ).then(
            fn=analyze_multiple_files, # Step 2: Run analysis
            inputs=[files, selected_model],
            outputs=analysis_outputs, # Update these components
            api_name="analyze"
        )

        # Chat toggle JS
        toggle_chat_js = """
        () => {
            const chatContainer = document.getElementById('chat-container');
            if (chatContainer) {
                    chatContainer.classList.toggle('visible');
                    // Optional: Focus the input when chat becomes visible
                    if (chatContainer.classList.contains('visible')) {
                         const chatInput = chatContainer.querySelector('textarea'); // Find the textarea input
                         if(chatInput) chatInput.focus();
                    }
            }
            return []; // JS functions should return something, often an empty list for Gradio
        }
        """
        chat_btn.click(fn=None, inputs=None, outputs=None, js=toggle_chat_js)
        # --- End Event Handlers ---

    gr.HTML("""
    <div class='footer'>
        🛡️ Enterprise Threat Analyzer Pro | Developed by <b>Ajmal Malayil</b> | Powered by Gemini AI
    </div>
    """) # Placeholder developer name

# Launch the Gradio app
if __name__ == "__main__":
    # Schedule cleanup periodically (e.g., every hour) if desired, otherwise it only runs on clear.
    # Note: Background scheduling needs libraries like 'schedule' and 'threading' and careful implementation.
    # For simplicity, cleanup_old_reports() is called by clear_outputs().

    print("Starting Gradio server...")
    demo.launch(server_name="0.0.0.0", server_port=10000) # share=True for public link (use with caution)
